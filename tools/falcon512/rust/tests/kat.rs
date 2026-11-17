//! The NIST round-3 KAT through the verifier with standard Falcon's
//! HashToPoint in place of this crate's: the decoding and the norm are v1.2's.

use apogee_falcon512::verify_point;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// The NIST round-3 KAT's Falcon-512 entries 0 and 1 (`falcon512-KAT.rsp`):
/// `pk`, `msg`, and `sm` converted to the padded v1.2 signature, `0x39 ‖ salt
/// ‖ compressed s2 ‖ zero padding`, 666 bytes.
const KAT: [(&str, &str, &str); 2] = [
    (
        concat!(
            "096ba86cb658a8f445c9a5e4c28374bec879c8655f68526923240918074d0147c03162e4a4920064",
            "8c652803c6fd7509ae9aa799d6310d0bd42724e0635920186207000767ca5a8546b1755308c304b8",
            "4fc93b069e265985b398d6b834698287ff829aa820f17a7f4226ab21f601ebd7175226bab256d888",
            "8f009032566d6383d68457ea155a94301870d589c678ed304259e9d37b193bc2a7ccbcbec51d6915",
            "8c44073aec9792630253318bc954dbf50d15028290dc2d309c7b7b02a6823744d463da17749595cb",
            "77e6d16d20d1b4c3aad89d320ebe5a672bb96d6cd5c1efec8b811200cbb062e473352540eddef8af",
            "9499f8cdd1dc7c6873f0c7a6bcb7097560271f946849b7f373640bb69ca9b518aa380a6eb0a7275e",
            "e84e9c221aed88f5bfbaf43a3ede8e6aa42558104faf800e018441930376c6f6e751569971f47adb",
            "ca5ca00c801988f317a18722a29298925ea154dbc9024e120524a2d41dc0f18fd8d909f6c5097740",
            "4e201767078ba9a1f9e40a8b2ba9c01b7da3a0b73a4c2a6b4f518bbee3455d0af2204ddc031c805c",
            "72ccb647940b1e6794d859aaebcea0deb581d61b9248bd9697b5cb974a8176e8f910469cae0ab4ed",
            "92d2aee9f7eb50296daf8057476305c1189d1d9840a0944f0447fb81e511420e67891b98fa6c2570",
            "34d5a063437d379177ce8d3fa6eaf12e2dbb7eb8e498481612b1929617da5fb45e4cdf893927d8ba",
            "842aa861d9c50471c6d0c6df7e2bb26465a0eb6a3a709de792aafaaf922aa95dd5920b72b4b8856c",
            "6e632860b10f5cc08450003671af388961872b466400adb815ba81ea794945d19a100622a6ca0d41",
            "c4ea620c21dc125119e372418f04402d9fa7180f7bc89afa54f8082244a42f46e5b5abce87b50a7d",
            "6febe8d7bbbac92657cbda1db7c25572a4c1d0baea30447a865a2b1036b880037e2f4d26d453e9e9",
            "13259779e9169b28a62eb809a5c744e04e260e1f2bbda874f1ac674839ddb47b3148c5946de01801",
            "48b7973d63c58193b17cd05d16e80cd7928c2a338363a23a81c0608c87505589b9da1c617e7b7078",
            "6b6754fbb30a5816810b9e126cfcc5aa49326e9d842973874b6359b5db75610ba68a98c7b5e83f12",
            "5a82522e13b83fb8f864e2a97b73b5d544a7415b6504a13939eab1595d64faf41fab25a864a574de",
            "524405e878339877886d2fc07fa0311508252413edfa1158466667aff78386daf7cb4c9b850992f9",
            "6e20525330599ab601d454688e294c8c3e",
        ),
        "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
        concat!(
            "3933b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d704c6d178429513",
            "090765843d1e460d17a527d2bca405bd55bbc7da09a8c620be0af4a767d9db96b80f55e466676751",
            "eaaba7b93b86d71132daa0eb376782b9eee37519ce10fdd33fe9f29312c31d8736206d165cf4c528",
            "aa3ddc017845e1f0dd5b0a44ff961c42d874a95533e5b438982f524ca954d87533bfbe42c63ff2ab",
            "c77a34c79db55a99171bbcb72c842a6530af2f753f0c34ac632f9f1e7949f0bf6c67665b27722a88",
            "57d626b6ff1a136d923a39f4069b7477ff946e5247a6627791d49b59edc9e2525a860e6e9828d18f",
            "64a9f17222e8166a02453859bbda0b8186d8c9928bb571e4146401d7430e225904673ad21ccac54c",
            "146c248a1dd69ab6491e901d6d71b152155be97de057f3916a3f1b4273308c29b2f4d9697167b906",
            "81b1583ed930a71e990467dea368134beceebd597f9bec922e816f1b0570d728f4ae0464c1f79765",
            "7f87a4e52dcdcaeb9272662ea66d7c6cd8781b31af555ad93f5f65e75816cb8dc306bb67e592b526",
            "1baca7c509629ea2af8abb80cba89ee535b76dfd9ccbbe3bf48f2bc8aa34b26e1103291053f5cb8d",
            "e3a45afa5a76df8b2122ed2c82fbcf2259290d41a14f86b12f35f5d49762b34cff13ee7e42edec70",
            "201d7f37c33316288fa3078e36e58108865c3cfe263d563692043decc62f3426f86061285b7b1b33",
            "6f56ff41bb65e9cd6d9b92fd90f864aa1c923cb8c755f5cde1770d862595427149d7721aaab5d194",
            "aea9acdeca15be43cba6a62b5a33909e9fc4da1c5814fbd7cd6a2fa572e318b42c6c319140b86e66",
            "392580a11a2b431f44c1f9270e4f7b2490f3b325a9977a71a575915636635b9969dbd6d220b24c3d",
            "99cebbbd834b88222bd08c3abe124e8000000000000000000000",
        ),
    ),
    (
        concat!(
            "09baccc8d6c916c9ad12e3e49881f732b84870ce5976921d197a00d226ab8825430da78f19b0e7a1",
            "2129ecb739d4a05c5ebb0019f0c610e14556a0b4c7a48e2e4cc851d2e8a57417e48f918b56dc605d",
            "25113451c3b10520f81c016a63c6f2d8826b90b04d8b0a792272607e39829adf4b09c0cafb11cf2f",
            "893c56b26420f84901ff072f9100013536822d512792643df4ede4b64200ae0bf82b7d46792eeae3",
            "571f501a9a814e69f21e84dc263457b913957886af9da2598003e853ac23b4d682971507b85bfeb1",
            "46010b4b0cdd3f00af806cbd56a32987e38532ae3c7794058215c5db042026ac7dfa58ea5b17b8ae",
            "91e06a07db253e21eff361ec063412b227fe2cf9592c6b4888589f0a3a7fb9a300b131fc4ae755ce",
            "16a1554be6ce0f4e8301bb814e2d1903a209f0744687024949876ac94187fce08655c2131f2a4488",
            "64cd6c77783ea2de6c1042c68e389f6d068eec2199dc9b6e92edd4469a923a683ab1c49557c19d9c",
            "c9a3822b628862a9e5df2b152f898172f3c5fda506c2b21e10ed39cc1cebf50b889c493e1b6614a5",
            "3c30ee7be94abe59d83c270350ad490e2f9205e5607ae9328322c60aacacea9af2a12114626964b6",
            "8af104aa3b34c1a9e0ae1885314891710b3ace65f54f40451abe425fd7af4218ffd067a2f61e32d8",
            "51831aab032c0fa95bcc5504fcf8c180a9ea6d14cb23e35df931c40766468487612a172575d0ba6f",
            "20c225ab82a562f0eef6d20ed239da08287dde67701d2c29368dbe52acbbe0f219200535add286e6",
            "eb88e4f1643e922b2accbe8a3b52737a60a4344544966e66b7da65657b5bde6343b5987111c68634",
            "46c04415e0d985ab534e1d7eac615dc08e8f3d2a73d6057418368ad1dfa7001e647876cd50d58976",
            "5695cf9715739e5d42fa684c51c9077a95e7eb31b87ba1808882b0cd9fa0f5d4f26d596af17f22dd",
            "09c18836106f5979203b01d10707840c80249f9b963080fd5221c250ae405f5a5d0c312b6ea8971a",
            "998324c542323808cc9a81a42aa9df3c9080bcb4cf5bd73dfe5c080ceaaa66e0fae05d88f23b7673",
            "2ba4094c2d30fd16d26ac4247291fa2543b7751eff202113588b76a1646ecc6aa17861db54d5adbb",
            "fd3ae11423f3a78e8342deee705e98bf8bda82731a520374c69c6593c5d755c498f7b454c0185758",
            "c94b580d4257d66f71ead38205e2cc717032f1865649642472c5f34e1854040c63369c8317c1fc37",
            "518b16637840a86627113e3809a700cc1b",
        ),
        concat!(
            "225d5ce2ceac61930a07503fb59f7c2f936a3e075481da3ca299a80f8c5df9223a073e7b90e02ebf",
            "98ca2227eba38c1ab2568209e46dba961869c6f83983b17dcd49",
        ),
        concat!(
            "3908e25538484cd7f1613248fe6c9f6b4ec14be684c6defdd1e41333b6e9052ac4340e314eea2c99",
            "f7e62b31023eb236b557957f7174885220923a7763217d9fe59b5ba53157ced51cd4d9ab93b38c66",
            "6d2047c4fa21aee43c95ea373f6d62f0e044bdb0be988685154ef7682617c7367b30d934b1d9c892",
            "29d281734a3005124b8d7c70b78e1634a3a20ccf9ab952c816dfad3d173567c139bdc624512f23f2",
            "a0c2f78c2be16d8f9b119d64ba6dec5e50ad104d8ba25edc9e53996f75d848caa0e4421167dd4d42",
            "d07d39c3e35d10924c1a8a9e098aa4d6112c67dbbf08c7a0888aeb657456c19e2259621edc3af897",
            "8de9c429b8167e679687a86cbb66403fbc6ee69f3f1344d07e845a865f22e5e94d9748cc12065fe1",
            "926d83cb288918c82d19fd5416de27576df8e45de1bd74351d996514748ae9018d27f57edb1de469",
            "75feba5e6d9bb1491c2a327bf158d03d2fbe0882ee0adc9b8121876dd9ef5c37f58d325af59b94df",
            "324cce5bc1216c8f4ecd0b4bb5728f83beeab09bfe3966cebdf4657ec6cfd773f0d5dba5bf28481d",
            "cb21aa1984e9c6d2168e350b4d6491d81967be0e354c869a8487f0f939f537a58df88abf2e4fadb5",
            "5250897a54a8475d160d697a77da36bbb1438245b35dee2ac791920c9fad8025adc8dfa88b168716",
            "c5a45075a3f9536bce6238e1ad4d41995d675d3cb71ad4ce33d0326ec2a9f5b9c1dc6750ecaa6aea",
            "ad4c0edcc4a5015eb3f7503ba2210b16665f889e4d1cf3a9e298d61b23846593fd4d772c646dd024",
            "823371d531094cbb17902db113796852161f5d2a12608b3c1bcece960aad07952671e4cd6186b7ec",
            "fbc7710258b8b26cfa3f1cecc61121a49dd276e4b124e3573ac8231b60c778e03b74926e2bfbecd4",
            "2f352bc325cf2204b3c0b5730e6188cfc0000000000000000000",
        ),
    ),
];

type Case = (Vec<u8>, Vec<u8>, Vec<u8>);

fn kat(i: usize) -> Case {
    let bytes = |hex: &str| test_support::hex_to_bytes(hex).expect("the KAT is hex");
    let (pk, msg, sig) = KAT[i];
    (bytes(pk), bytes(msg), bytes(sig))
}

/// Standard Falcon's HashToPoint: SHAKE256 of the salt and the message, read
/// as 16-bit big-endian samples `t`, each below `5q = 61445` taken in turn,
/// coefficient `i` the `i`-th one mod `q`.
fn shake_point(salt: &[u8], msg: &[u8]) -> [u16; 512] {
    let mut xof = Shake256::default().chain(salt).chain(msg).finalize_xof();
    let mut c = [0; 512];
    let mut i = 0;
    while i < 512 {
        let mut t = [0; 2];
        xof.read(&mut t);
        let t = u16::from_be_bytes(t);
        if t < 61445 {
            c[i] = t % 12289;
            i += 1;
        }
    }
    c
}

/// Whether `sig` verifies, its point from its salt and `msg` by SHAKE256.
fn verifies((pk, msg, sig): &Case) -> bool {
    verify_point(pk, &shake_point(&sig[1..41], msg), sig)
}

#[test]
fn the_round_3_kat_verifies() {
    assert!(verifies(&kat(0)) && verifies(&kat(1)));
}

/// A bit of the message, of the salt, of `s2` and of the padding flipped: none
/// verifies.
#[test]
fn an_altered_entry_does_not_verify() {
    let flip = |bytes: &[u8], at: usize, bit: u32| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1 << bit;
        bytes
    };
    for (pk, msg, sig) in [kat(0), kat(1)] {
        assert!(!verifies(&(pk.clone(), flip(&msg, 16, 0), sig.clone())));
        assert!(!verifies(&(pk.clone(), msg.clone(), flip(&sig, 18, 3))));
        assert!(!verifies(&(pk.clone(), msg.clone(), flip(&sig, 141, 5))));
        assert!(!verifies(&(pk, msg, flip(&sig, 665, 0))));
    }
}
