//! `bench recurse`: a base block proof's recursion tree, proved node by node
//! (`docs/spec/recursion.md` §8.4).
//!
//! ```text
//! bench recurse <dir>/<stem> --out <dir> [--leaf <shards>] [--budget <rows>]
//!     [--fan-in <k>] [--in-flight <n>] [--shards-in-flight <m>] [--limit <shards>]
//! bench recurse-node <out> <id> [--shards-in-flight <m>]
//! ```
//!
//! **The tree is fixed before anything is proved** (`host::recursion::Tree`):
//! leaves of consecutive base shards — at most `--leaf` (32), and by an
//! estimate of their folds' `FQ_OP` rows at most `--budget` (750,000, which
//! with a node's fixed MSM work fills one `2^20` shard) — then levels of
//! internal nodes over at most `--fan-in` (4) and at least two children, a
//! group of one carried up a level as it is. `--limit` plans over the base
//! statement's first shards only, which proves everything but the root's
//! claim to the whole statement.
//!
//! **A node is a process**, `bench recurse-node`: it reads the tree, the two
//! recursion programs and its children's proofs from `<out>`, builds its
//! advice only then, proves, verifies and writes `<out>/<id>.block`. So a
//! node's memory is its process's alone, and a node may as well run on
//! another machine that shares the directory. The scheduler keeps at most
//! `--in-flight` (1) of them running, each node started the moment its last
//! child's proof exists, in tree order, and each proving at most
//! `--shards-in-flight` (1) shards at once. A node whose proof is already in
//! `<out>` is not proved again, so a stopped run resumes.
//!
//! At the root, the scheduler verifies the proof and its journal: the
//! statement's shards covered, the two identities, and the accumulator's one
//! pairing check — what a verifier of the tree owes beside the root's own
//! proof (`docs/spec/recursion.md` §8.2).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use field::Fr;
use host::recursion::{self, Tree, TreeNode};
use verifier_core::node::{journal, node_image, BaseKey, Kind, ProgramKey};
use verifier_core::{BlockProof, VerifyingKey};

pub fn usage() -> &'static str {
    "bench recurse <dir>/<stem> --out <dir> [--leaf <shards>] [--budget <rows>] \
     [--fan-in <k>] [--in-flight <n>] [--shards-in-flight <m>] [--limit <shards>]\n\
     \x20   prove a base block proof's recursion tree, node by node\n\
     bench recurse-node <out> <id> [--shards-in-flight <m>]\n\
     \x20   prove one node of a planned tree; `recurse` runs it"
}

/// The ceremony at `2^24`, the recursion format's stacking height, cached
/// beside the system's temporary files after the first ingest.
fn srs() -> Result<srs::Srs, String> {
    let cache = std::env::temp_dir().join("apogee-ceremony-24.srs");
    if let Ok(srs) = srs::Srs::load(&cache) {
        return Ok(srs);
    }
    let ptau =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/ptau/ppot_0080_24.ptau");
    let srs = srs::Srs::from_ptau(&ptau, 24).map_err(|e| format!("{}: {e:?}", ptau.display()))?;
    srs.save(&cache)
        .map_err(|e| format!("{}: {e:?}", cache.display()))?;
    Ok(srs)
}

/// A recursion program's prover setup, over its ELF under its parameters.
fn setup(elf: &[u8], params: program::ProgramParams) -> Result<prover::ProverSetup, String> {
    let image = loader::load_elf(elf).map_err(|e| format!("{e:?}"))?;
    let (tables, config) = program::decode_program(&image, &params).map_err(|e| e.to_string())?;
    let program = prover::Program {
        image,
        tables,
        config,
    };
    prover::ProverSetup::new(program, srs()?).map_err(|e| format!("{e:?}"))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn split_stem(path: &Path) -> Result<(&Path, String), String> {
    let stem = path
        .file_name()
        .ok_or("a proof archive's <dir>/<stem>")?
        .to_string_lossy()
        .to_string();
    Ok((path.parent().unwrap_or(Path::new(".")), stem))
}

struct Options {
    archive: PathBuf,
    out: PathBuf,
    leaf: usize,
    budget: u64,
    fan_in: usize,
    in_flight: usize,
    shards_in_flight: usize,
    limit: Option<usize>,
}

fn options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        archive: PathBuf::new(),
        out: PathBuf::new(),
        leaf: 32,
        budget: 750_000,
        fan_in: 4,
        in_flight: 1,
        shards_in_flight: 1,
        limit: None,
    };
    let mut at = 0;
    let mut archive = None;
    while at < args.len() {
        let value = |at: usize| {
            args.get(at + 1)
                .ok_or(format!("{} needs a value", args[at]))
        };
        let number = |at: usize| -> Result<usize, String> {
            value(at)?.parse().map_err(|e| format!("{}: {e}", args[at]))
        };
        match args[at].as_str() {
            "--out" => o.out = PathBuf::from(value(at)?),
            "--leaf" => o.leaf = number(at)?,
            "--budget" => o.budget = number(at)? as u64,
            "--fan-in" => o.fan_in = number(at)?,
            "--in-flight" => o.in_flight = number(at)?,
            "--shards-in-flight" => o.shards_in_flight = number(at)?,
            "--limit" => o.limit = Some(number(at)?),
            other if !other.starts_with("--") && archive.is_none() => {
                archive = Some(PathBuf::from(other));
                at += 1;
                continue;
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        at += 2;
    }
    o.archive = archive.ok_or("recurse needs a proof archive's <dir>/<stem>")?;
    if o.out.as_os_str().is_empty() {
        return Err("recurse needs --out <dir>".into());
    }
    if o.fan_in < 2 || o.leaf == 0 || o.in_flight == 0 || o.shards_in_flight == 0 {
        return Err("--fan-in is at least 2, the rest at least 1".into());
    }
    Ok(o)
}

/// `bench recurse`: plan, set the two programs up once, and run the nodes.
pub fn run(args: &[String]) -> Result<(), String> {
    let o = options(args)?;
    std::fs::create_dir_all(&o.out).map_err(|e| e.to_string())?;
    let (dir, stem) = split_stem(&o.archive)?;
    let (base_vk, _, _, block) = host::proof_archive::read_proof(dir, &stem)?;

    // The two programs, built once: their ELFs, held to the keys their images
    // were built from, and their verifying keys.
    let leaf_elf = host::fixture::build_guest("recursion", "leaf")?;
    let node_elf = host::fixture::build_guest("recursion", "node")?;
    let guest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guests/recursion");
    if read(&guest.join("base.key"))? != BaseKey::of(&base_vk).to_bytes() {
        return Err("guests/recursion/base.key is not this archive's key: \
                    run `profiler base-key` on it first"
            .into());
    }
    let keys = recursion::program_keys(&leaf_elf, &node_elf)?;
    if read(&guest.join("programs.key"))? != ProgramKey::list_to_bytes(&keys) {
        return Err("guests/recursion/programs.key is not the two programs': \
                    run `profiler program-keys` first"
            .into());
    }
    let t = Instant::now();
    for (name, elf, params) in [
        ("leaf", &leaf_elf, recursion::leaf_params()),
        ("node", &node_elf, recursion::node_params()),
    ] {
        let vk = setup(elf, params)?.vk;
        std::fs::write(o.out.join(format!("{name}.elf")), elf).map_err(|e| e.to_string())?;
        std::fs::write(o.out.join(format!("{name}.vk")), vk.to_bytes())
            .map_err(|e| e.to_string())?;
        println!("{name}: identity {}", hex(&vk.identity.0.to_bytes()));
    }
    println!(
        "the two programs set up in {:.1} s",
        t.elapsed().as_secs_f64()
    );

    // The tree.
    let mut costs = recursion::shard_costs(&block);
    if let Some(limit) = o.limit {
        costs.truncate(limit);
    }
    let tree = Tree::plan(&costs, o.leaf, o.budget, o.fan_in);
    let text = format!("base {}\n{}", o.archive.display(), tree.to_text());
    std::fs::write(o.out.join("tree.txt"), &text).map_err(|e| e.to_string())?;
    let leaves = tree
        .nodes
        .iter()
        .filter(|n| matches!(n, TreeNode::Leaf { .. }))
        .count();
    println!(
        "{} nodes over {} base shards: {} leaves, root {}",
        tree.nodes.len(),
        costs.len(),
        leaves,
        tree.root
    );

    // The nodes: each started when its children are proved, at most
    // `in_flight` at once.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let proof = |id: usize| o.out.join(format!("{id}.block"));
    let mut done: Vec<bool> = (0..tree.nodes.len()).map(|id| proof(id).exists()).collect();
    let mut running: Vec<(usize, Child, Instant)> = Vec::new();
    let begun = Instant::now();
    while !done[tree.root] {
        let ready = (0..tree.nodes.len()).find(|id| {
            !done[*id]
                && !running.iter().any(|r| r.0 == *id)
                && match &tree.nodes[*id] {
                    TreeNode::Leaf { .. } => true,
                    TreeNode::Internal { children } => children.iter().all(|c| done[*c]),
                }
        });
        if let (Some(id), true) = (ready, running.len() < o.in_flight) {
            let log = std::fs::File::create(o.out.join(format!("{id}.log")))
                .map_err(|e| e.to_string())?;
            let err = log.try_clone().map_err(|e| e.to_string())?;
            let child = Command::new(&exe)
                .args(["recurse-node", &o.out.to_string_lossy(), &id.to_string()])
                .args(["--shards-in-flight", &o.shards_in_flight.to_string()])
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(err))
                .spawn()
                .map_err(|e| e.to_string())?;
            println!("node {id} ({}) started", describe(&tree.nodes[id]));
            running.push((id, child, Instant::now()));
            continue;
        }
        if running.is_empty() {
            return Err("no node is ready and none is running".into());
        }
        std::thread::sleep(Duration::from_millis(500));
        let mut finished = None;
        for (k, (id, child, started)) in running.iter_mut().enumerate() {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                if !status.success() {
                    return Err(format!(
                        "node {id} failed ({status}): see {}",
                        o.out.join(format!("{id}.log")).display()
                    ));
                }
                println!(
                    "node {id} proved in {:.1} s",
                    started.elapsed().as_secs_f64()
                );
                finished = Some(k);
                break;
            }
        }
        if let Some(k) = finished {
            let (id, _, _) = running.remove(k);
            done[id] = true;
        }
    }
    println!("the tree proved in {:.1} s", begun.elapsed().as_secs_f64());
    check_root(&o.out, &tree, costs.len(), &base_vk)
}

fn describe(node: &TreeNode) -> String {
    match node {
        TreeNode::Leaf { from, to } => format!("leaf over base shards {from}..{to}"),
        TreeNode::Internal { children } => format!("internal node over {children:?}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{b:02x}")).collect()
}

/// What a verifier of the tree owes beside the root's proof: the root
/// verifies under its program's key, its journal covers the shards planned
/// and requires the two published identities, and its accumulator
/// discharges.
fn check_root(
    out: &Path,
    tree: &Tree,
    shards: usize,
    base_vk: &VerifyingKey,
) -> Result<(), String> {
    let kind = match tree.nodes[tree.root] {
        TreeNode::Leaf { .. } => "leaf",
        TreeNode::Internal { .. } => "node",
    };
    let vk = VerifyingKey::from_bytes(&read(&out.join(format!("{kind}.vk")))?)
        .map_err(|e| format!("{kind}.vk: {e:?}"))?;
    let block = BlockProof::from_bytes(&read(&out.join(format!("{}.block", tree.root)))?)
        .map_err(|e| format!("the root's proof: {e:?}"))?;
    verifier::verify_block(&vk, &block, block.statement())
        .map_err(|e| format!("the root does not verify: {e:?}"))?;
    let cells: Vec<Fr> = block
        .statement()
        .output
        .chunks_exact(32)
        .map(verifier_core::tape::imported)
        .collect();
    if cells.len() != journal::CELLS {
        return Err("the root's journal is not a node's".into());
    }
    let small = |k: usize| Fr::from_u64(k as u64);
    if cells[journal::FROM] != small(0) || cells[journal::TO] != small(shards) {
        return Err("the root does not cover the shards planned".into());
    }
    if kind == "node" {
        let leaf = VerifyingKey::from_bytes(&read(&out.join("leaf.vk"))?)
            .map_err(|e| format!("leaf.vk: {e:?}"))?;
        let ids = [leaf.identity.0, vk.identity.0];
        if cells[journal::IDENTITIES..journal::IDENTITIES + 2] != ids {
            return Err("the root does not require the two programs' identities".into());
        }
    }
    let vsrs = verifier::decode_srs_verifier(&base_vk.srs_verifier)
        .ok_or("the base key's SrsVerifier holds a point that is not one")?;
    let point = |at: usize| {
        let mut bytes = [0u8; 64];
        for (k, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&cells[at + k].to_bytes()[..8]);
        }
        curve::G1Affine::from_bytes(&bytes).ok_or("the accumulator is not a point")
    };
    let (a, b) = (point(journal::A)?, point(journal::B)?);
    if !curve::pairing::pairing_check(&[(a, vsrs.g2_gen), (-b, vsrs.g2_tau)]) {
        return Err("the root's accumulator does not discharge".into());
    }
    let whole = if shards == journal_total(&cells) {
        "the whole base statement"
    } else {
        "a prefix of the base statement"
    };
    println!("the root verifies: {whole}, {shards} shards, its accumulator discharging");
    Ok(())
}

/// The base statement's shard count, as a journal carries it.
fn journal_total(cells: &[Fr]) -> usize {
    let bytes = cells[journal::TOTAL].to_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
}

/// `bench recurse-node <out> <id>`: one node of `<out>/tree.txt`, proved.
pub fn node(args: &[String]) -> Result<(), String> {
    let [out, id, rest @ ..] = args else {
        return Err("recurse-node needs <out> <id>".into());
    };
    let shards_in_flight = match rest {
        [] => 1,
        [flag, n] if flag == "--shards-in-flight" => n.parse().map_err(|e| format!("{e}"))?,
        _ => return Err("recurse-node takes only --shards-in-flight".into()),
    };
    let out = PathBuf::from(out);
    let id: usize = id.parse().map_err(|e| format!("the node's id: {e}"))?;
    let text = String::from_utf8(read(&out.join("tree.txt"))?).map_err(|e| e.to_string())?;
    let (first, rest) = text.split_once('\n').ok_or("tree.txt is empty")?;
    let archive = PathBuf::from(
        first
            .strip_prefix("base ")
            .ok_or("tree.txt names no base")?,
    );
    let tree = Tree::from_text(rest).ok_or("tree.txt does not read")?;
    let (dir, stem) = split_stem(&archive)?;
    let (base_vk, _, _, base) = host::proof_archive::read_proof(dir, &stem)?;
    let vk_of = |name: &str| -> Result<VerifyingKey, String> {
        VerifyingKey::from_bytes(&read(&out.join(format!("{name}.vk")))?)
            .map_err(|e| format!("{name}.vk: {e:?}"))
    };

    let t = Instant::now();
    let (setup, run) = match tree.nodes.get(id).ok_or("no such node")? {
        TreeNode::Leaf { from, to } => {
            let setup = setup(&read(&out.join("leaf.elf"))?, recursion::leaf_params())?;
            let words = recursion::leaf_image(&base_vk);
            let run = recursion::leaf(&base_vk, &words, &base, *from as usize..*to as usize)?;
            (setup, run)
        }
        TreeNode::Internal { children } => {
            let setup = setup(&read(&out.join("node.elf"))?, recursion::node_params())?;
            let elves = [read(&out.join("leaf.elf"))?, read(&out.join("node.elf"))?];
            let keys = recursion::program_keys(&elves[0], &elves[1])?;
            let words = node_image(Kind::Internal, &BaseKey::of(&base_vk), &keys);
            let (leaf_vk, node_vk) = (vk_of("leaf")?, vk_of("node")?);
            let blocks = children
                .iter()
                .map(|c| {
                    BlockProof::from_bytes(&read(&out.join(format!("{c}.block")))?)
                        .map_err(|e| format!("child {c}'s proof: {e:?}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let children: Vec<recursion::Child> = children
                .iter()
                .zip(&blocks)
                .map(|(c, block)| {
                    let leaf = matches!(tree.nodes[*c], TreeNode::Leaf { .. });
                    recursion::Child {
                        vk: if leaf { &leaf_vk } else { &node_vk },
                        block,
                        program: if leaf { 0 } else { 1 },
                    }
                })
                .collect();
            let ids = [leaf_vk.identity.0, node_vk.identity.0];
            let run = recursion::internal(&words, &children, ids)?;
            (setup, run)
        }
    };
    println!(
        "node {id}: set up and advised in {:.1} s",
        t.elapsed().as_secs_f64()
    );

    let t = Instant::now();
    let io = emulator::GuestIo {
        input: Vec::new(),
        advice: run.advice,
    };
    let (block, _) = prover::prove_block_streaming(&setup, &io, shards_in_flight)
        .map_err(|e| format!("proving: {e:?}"))?;
    verifier::verify_block(&setup.vk, &block, block.statement())
        .map_err(|e| format!("the proof does not verify: {e:?}"))?;
    let native: Vec<u8> = run.journal.iter().flat_map(|v| v.to_bytes()).collect();
    if block.statement().output != native {
        return Err("the proved journal is not the native one".into());
    }
    println!(
        "node {id}: {} shards proved and verified in {:.1} s",
        block.shard_proofs().len(),
        t.elapsed().as_secs_f64()
    );
    let path = out.join(format!("{id}.block"));
    let partial = out.join(format!("{id}.block.partial"));
    std::fs::write(&partial, block.to_bytes()).map_err(|e| e.to_string())?;
    std::fs::rename(&partial, &path).map_err(|e| e.to_string())
}
