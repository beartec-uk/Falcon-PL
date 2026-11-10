// Copyright (c) 2025-2026 BEARTEC. All rights reserved. See LICENSE.
//! v2.9.62 "rewards-v2": activation constants and confirmed parameters
//! (Scott, 13:44 BST 9 Oct 2026; see docs/ops/REWARDS_IMPLEMENTATION_PLAN.md).
//!
//! **Unarmed by default.** `TESTNET_2300_REWARDS_V2_FROM_HEIGHT = u64::MAX`
//! means no rule in this module changes behaviour. A separate arming commit
//! sets the real `H_act` (above tip + roll margin) before the coordinated roll.
//!
//! Two gates:
//! - **`H_act`** (height): consensus safety rules (rail duplicates, bond
//!   hygiene, admission, escrow, min bond, equal lottery, seed, timestamps,
//!   inactivity) apply to txs/ledgers at `height >= H_act`.
//! - **`E_v2`** (epoch): the rewards formula and the counters it uses
//!   (persisted watcher slot bitsets, proposer/vote credits, fee share,
//!   LP value weights, interest) apply to epochs `>= E_v2`, and only once
//!   `H_act` is armed and reached. The arming commit must pick `H_act` so
//!   it is reached **before** epoch `E_v2` starts.
//!
//! Devnet: on networks other than 2300 the env overrides
//! `FPL_REWARDS_V2_FROM_HEIGHT` / `FPL_REWARDS_V2_EPOCH` are honoured, so a
//! local rehearsal can activate early. They are ignored on 2300.

use crate::NETWORK_ID_PUBLIC_TESTNET_2300;

/// `H_act` on 2300 (armed 9 Oct 2026 15:15 BST on Scott's GO 15:10): tip
/// 414,849 at 15:10:42 BST, ~1,150 blocks/h → ≈ 19:40 BST Fri 9 Oct. Roll
/// must finish (all 7 seats on 2.9.62) by `H_act − 2,000` = 418,000 (≈ 17:45).
pub const TESTNET_2300_REWARDS_V2_FROM_HEIGHT: u64 = 420_000;
/// First epoch (1-based) settled with the v2 formula on 2300. Rule (Scott):
/// 9 if all seats are on 2.9.62 and `H_act` is reached by ~Sat 20:00 BST,
/// else 10.
pub const TESTNET_2300_REWARDS_V2_EPOCH: u64 = 9;

/// Confirmed parameters (D1–D9).
pub const FEE_BURN_PCT: u64 = 50;
pub const FEE_PROPOSER_PCT: u64 = 30;
// The pot gets the remainder (20%).
pub const POT_PROPOSER_PCT: u64 = 50;
pub const POT_VOTER_PCT: u64 = 40;
// Floor gets the remainder (10%).
pub const TX_BONUS_CAP: u64 = 64;
pub const BLOCK_BASE_CREDIT: u64 = 64;
pub const MIN_BOND_V2: u64 = 50_000;
pub const MISSED_TURNS_INACTIVE: u64 = 20;
/// Consecutive pack-or-certificate-vote events a locked seat must post,
/// with no missed own turn in between, before it earns again.
pub const EARN_STREAK_NEED: u32 = 20;
/// Floor weight is 0 when a seat was present for less than half the epoch.
pub const FLOOR_PRESENCE_MIN_NUM: u64 = 1;
pub const FLOOR_PRESENCE_MIN_DEN: u64 = 2;
pub const ARCHIVE_FLOOR_BPS: u64 = 10_500;
/// Never inactivate below this many eligible seats (committee size).
pub const MIN_ELIGIBLE_SEATS: usize = 6;
/// A round-0 miss counts only when this seat packed or voted within this
/// many blocks. Older than that, it is still catching up: the miss is not
/// counted and it is not marked inactive. 256 covers 20 draws across the
/// 9-seat lottery, so a seat that is at the tip and then dies still reaches
/// the inactive floor. A seat 1,000 blocks behind does not.
pub const CATCHUP_MISS_WINDOW: u64 = 256;

/// First height of the catch-up miss rule on 2300. `u64::MAX` leaves the
/// live rule unchanged. Arm only after every packing seat is on this binary:
/// the height is when `last_active_height` joins the state root.
/// Armed above the 2026-10-10 tip (~436900) so every packing seat is on
/// this binary before `last_active_height` joins the state root.
pub const TESTNET_2300_CATCHUP_MISS_FROM_HEIGHT: u64 = 441_000;

pub fn network_catchup_miss_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_CATCHUP_MISS_FROM_HEIGHT;
    }
    env_u64("FPL_CATCHUP_MISS_FROM_HEIGHT").unwrap_or(u64::MAX)
}
/// sealed_at may be at most this far ahead of the checker's local clock.
pub const SEALED_AT_MAX_AHEAD_MS: u64 = 5_000;
/// ...except a step of up to this much over the parent is always allowed
/// (liveness when the chain clock is already ahead of wall time).
pub const SEALED_AT_MIN_STEP_ALLOWED_MS: u64 = 1_000;

/// A10 admission public key (Falcon-512 hex) on 2300. **PLACEHOLDER**: empty
/// until Scott provides the public key. Empty = fail-closed (no new seats can
/// be approved or bonded once `H_act` is reached). Must be set before arming.
pub const ADMISSION_PUBKEY_2300: &str = "0940fdc0c9685f8a3958c5f2214361b8cefa56f3430780804fbac71391421926751c16bf8006479921466a04546af2c78d17062c60276f00fb87368737c1e8be99140ae78f489c0ec4b732f1963a98e236ea9ecef58bb54b35b7d528be2afc209ec53a243ab1f1cfed1272c878009348e71a3025a66b936054726bf0bfa406195651a0e64f5d2bf2b3324e5d87a04cffb70b550f3ab03cf7720b8fa56ccd39b7c7db73ea02754dc30a1df429833b2e62022629a7ae6e331fc8d497fcddad3e2ad862686dad80d6b0623cc36a00f9c2715786862959a7c25fd3b60b94f79622cd8e2fd9323b32d40467701b3a42617d9e20b499504f5e2b8260a60184ea905e91668620744b09e9e09daeda2242aaf317d45f6481b2abae2876959a63611a04905bea0079494d298fd5bb657ccdd77d298c63d7edd1a9f29c399fdfb014668dc7f32969a54906aad425c675dde900a4ed0b6d5622540827729d75a7b7982364752a7a925c47be92826d5ba91014ad0461908e08c017854aa258c11d8969166767ccfba79ee15ba7e0f34999c86b7e5fcbbb757f80cea65227827b376ced81722450752dc839543cf8196065d3338cc5a437e8d91fbd4ea11adaef38f2d28201462977505e9b082358b1ad0cab5edad224ae5c6b8dec7d48c00d29139f36511e1781cc845ca5348f919be1d920dd4d474b15b068e232c60d1c476e4664123bce02aba448907b0220591050e29554c71d31d489c2d462970e94f7bd09e111012ec242ae8f305a70c104a9bd4618f9e546e93649fa5164e38cae9b1018a79b50cf1b058e18f72d4e17dc6852114d3d92e14a30a8022b537ebe797f43335e82a4044d4add21a5ac27d10578815c2458dca44f21558a440c58f3ac7011e3ea0b7c62221978600c8b4cddccbb03d6a59174c8f0f3e258ae366050709084827dd610d85c0da741fcb097a09f59e9c02bd7cd1c595e3d29c201112ff5d0f794aabd0088ac55826b0d148e0ab9189f9a5b7a6ca84a48ac21663a86df93f820f9724b51a22983aa5f80c7ce6f0ac463db34a2426a90e57a1fc106962e4a9026134a7fb957126151fa68257508ef82123941776169abc8895caa90a8e53104ae75310866702120c22ae49f55b85ecb852b1eabb12ddad0dac40102bd6969d75d3fb330d6947354a60bdd8178839cb56eec3040b420ec6945fd23a28b273dc995c205848e3add4913a216229aedf711dc6b6b6b4437c5d155d97e6e8bbbfe1e3d0cfd85e606aee6";

/// A13 registered keys of the pre-v2 (legacy) seats on 2300, `(id, falcon-512
/// public key hex)`. From `H_act`, consensus votes and certificates verify only
/// against these (legacy seats) or the on-chain BondV2 key (v2 seats); any
/// other bonded id goes inactive at `H_act`. **Must be filled by the arming
/// PR** (the node refuses to start armed on 2300 with this empty).
pub const TESTNET_2300_SEAT_KEYS: &[(&str, &str)] = &[
    ("v1", "09a93987f1dfeb448e6a78854f61cd122ae1c70a88cc962c6883729ee50e9085b47186a757816d821705e1b9ad5e91a521f329f955141050cd0fb5709303634f776a6975eaebcf301492d83c914575e128a023d3f49955b897849b4e81b286ab5722bba47654d8984a081524a742118a3e2cc4188916abe973021fa39f92b2607d06d46ed2bf6c485ab116c22c61493d02c610ac95ba164a9d677715dc8d46a9825a0cbacbb5734f181eddb3f5c3a0577fba5eda422feca872f4b4ea696c041403e44a8a4b7e90a9b6b0a16e5b61fbc55b6e4f989196553c69a751a820d0036373a92a8562bfeebb1a613418b263abac5c435b805e2c519ab9cad7d89d7d657706e38859650195b526d4cbb50485f66ca12fb7207ac140686981063ed8bbd4719519057a8fe887995e89b06490f102aa119b6286336acd482863ad227660dc56f312984d919f1ac00e307c45f692ede26ba27d54c67ac05ebc5e3c642f245607ad0e91345a6b68f834d7ae12c89e10f91c001caf8dbd5f8b95592a1621b173876d98b8cef86ab1db9fbe4a847a7aed248c9a6bb03f5c09bc486231748b5e02b0f466ababbc33b566758c69214decbae1fb9dc1933e6629f7996d0ce936a15c576f78307d1163afcbbf4db4e90c6b438bec00a633e6c681be5936ae87798e0680d777c93c14740c07a8c0556df96700d60ced0ebe04e1dd969abadedd037229df68f6f266b215522c02971a364a1448680ae0271e254ea6b6a0bd6c351b803fe1dd8bc6345b0006fa5f337a968b12ed5d83653dc2d89186f61a6c857b1a8297372cc91524de98168aa087d75d6f20d0174749a960427093413b58d608e2a7490994d7301888a5fd04d806b9361af345a8359a731b53cd7213514dda44df3015300b20aec3667329f3da869c045c306a95eda13f6021671a3a6b0d26ac4530c0a4960aa4dd68374d471c8db4c50de2589036a652f25d903c89f19b28df199022753b8142c21b1a8a31eb92463ab1b284a8eb0e91f643123b067806492b0317e084783292cbc7d1fc57592160c21a691a603da18c02414850bc212393894e8e48c57384576b04c916ec965536c1b551fa99cb7e785b07a04e6447f6b5801801e2afd69318cd0f999d3dd5f7546fff3ffd9324be51eb35ca06daaadaba43401fe1c2042f57f817d463cff079dc8f6369d9895940f3a9202ed97a0e81664256feaa7d1da165976d1510ecd534e86a6fb2fb1aaa6c2177e52786ee1e0118801c61f55174"),
    ("v3", "09b2d19cdbe02ab7348d945b13c702b0f9d4b75fc25c540a079b3a9b26b51680cbcf479d0fd8eb8b7202d7022ca94404ec30b9b81cd09b190f82eaa35bc51f37aeb85273f49d55ad524b304320b40ec0f142c56e687e29ddf493cab918d02422ae9b48aea4b17620623d7fe5c15b7053428f99d5a8961ff2834a1d281b873971627205124a6892e9b15958401f1f39d2c783949463106a94f0509f6814bf820a47306d425185cc842780deba45354eca8cf95977be26d13d21fab361d19ba7d5785bb55de5111c9b03ed90c49430be50b10d87bb82a520451957bce67ba181a4a80138ec7a42a21613608f5902dd67b875b13590dcdea2d174284823840f2c6f2a83680896baa1b60e8c8754598dbab6098f70042d71c02f4157f0e13aed9a90a61ae500979fca774450c8f84379147522e6e0e4088c6289a82a06d921fee902475d847c3977b3d58dc600d4e511066501a9e6e89a3cd4d76ad0a3b13b62fd1f5d9c277d6b3d2eecc2e5ec5ba98124b65902113e80b654556e487429fa8026b6cc261cb4628853493d55298b21251c747b199155e06aa53851c660420d4d17d58d060d6ef0ac5435cbb2076d3bdcf743751657556d7da78b90b372995b44774e9d5476128357ae659c46c473c664691fd0d33b20010344e5e3d356838a075ad707e7d5b98146f9f5f4ee430c9c7fb6c9de939a55cbe2a2ee0f9ec5b20ae2659dbe3a8e66f292e68dc10385fd69e54405cf466782091a4261694f52f5bd391b342d93e8254eceb46ec97c2a0e759517211aa31a99c6d218550058a071e60d01a6b62f8923567289b61cdb46c7a825b525d0b1dc618f4cb8c23d988168c64da3f52cef055282e471644c853587ba85843b4ab51fb1c145496b481fc33f4642b248a6b28748ca306e83da4529922570213a0742c842b91938da13a5316551f43f250595dc4a409b14fbb57daae71ece240511696a11478fbe76dcb61be984af4978f19b58da82606f14548c53a321a26317e56aac6999e03bde142a1c6be82d69049cc9fe05a826579d0d54267562506f6cebc25f066138587f056998de0a39b052eee1197472d952800c9b200a9e7383a365126426dbb25b96732a2c60a5c9cebf7e81f2ac06236ae4d9c8106d9a60915d4073a69c9c61281693dad055f8739b9a4d513dbed2b6a4cc2b1c4d526061d1227a1aeb320e83d78fe1005a60abddaa022ffafc89cda46400b4389c178ea5a439d8e0c136b055d58da93753b24290864dad"),
    ("v6", "09516c07da5ea36d6bcedd73e9e73c45a5fc62696b4272c8dc0691109a0844d4b13162f83931ec2890d7dbad5daae080dab35884ad8a041f53b56932d0670b3db5016ec2ea20502c8a5387df6f1996713cf66fe44673c5ce633586356caa03a10b1efc5e04c92065e21b469012064363ca8e2ab7e4b9c059a4dd8f78404c012ff1103336aef2aeb40893059d384eaae9aaf71119b8e975d336c47745f4ab2a73255e7be516aa6f04093c46db806745907959c460ccc178249d4e919de7283428f6578ee7dd1568f4b2e8c32262f5f315fc22fa0cb0eeb73a1c733bf83e70b24b1821902433ce64f598d678c282a9643c7da8385288ac77123bb83b5ef52c2db87671c23e5dc096e1cd0b00270c07c8ce1adb133cca942084515190d4e03d093670d0c7db9ecba2aa08c161698f921fde7fe4c0a0d6a2a690d31a8b7b0f86e616a0e5c934747ab54de4e0bf80081bb8de180380e4e84e6cf9a774a574c7267d555937263b4c623906a52aed90a72b6aaa95fea3c81409224620df509d09bebb9b03d86f5a391a2de1e902926b172ea1b176dcce75cb5ca4649a22d2ebd3741e6de14474d9737f9aeed7f5d7677176d4b2a45e3ca15573c64c188656dca72a4622756b249e90ce0e57113e9f7918a542342ded96220a9a686ed751a28958a9204d7bfe1d694534c5865728c1ad622233380eebab01e636ae83de29e8ba48e7de9b793978489f459da57a3845294c5d9e98aa3beb90a88ed8346850525186113f3bc66b5011d5dad795db0e850502995c1b9c45105f142655b5b560d55907ee9873d2a5d9f383de08d01dc3151835193cbf76a61166a3827a249816f207246cda0bc391ad0d51a0821bd50828c9c43026ce8c62d710ce97cd512601086f87bf6ede1777cb518864d8c69288d6c29efdb52604c91a78223974de08874fb549c51e6ba4106270e6b619a94a39e8e9b0905e270202c16423ce143687f911a65ca4917db3fd5bbc933e28395b1750895450542eacd35ac11785f112809970b983611f10a775fa857e5ae9121566044e594b6ea28b461f66df699c38b2b454fd80def57413576fb3adef061a14e6b97da283834d38109055f3ab4e5a982668320e479a95f2c0442c8830b1a080bb391acc9024861bb72bcebf742963278e2cbc083229a3cd820a4d78ba69a90f6e82cd99ec5d1a98769c5535939b1bd4607aa6ec8dac51cb55bc62cc13c253b700d56a508854c07447d0721606a31ac8693a4c43b4d7a13f"),
    ("v10", "09636e85954b2516545549f1830c7265d187d87d588c550a0ab1afe99387e5d88956280a2c08a5219e5f813474ff056aa2c88080560b624de47965f2d74dace722aace23744b3732860aaa0cc67b25e5d9fb0457653f464410d21ae9acada485442e6cbb3462a77c1c473a79a9e9abd1325c16053a13e2278864f72596ab98946472b88754b82e9ac0d9f111f296c559a375606b728a6a6882efdc80b072f0466ffa464d5e4a0f2c752c81db3b842e3d3ae8b35066c7db170a6873cf2032bc456fa3baae5c4918bc7710d4110e58939ac827cc8a963ad9bea26858c89295cf9cce8a1a747654094b1d7c6b812ac3658be1cd99e5873a1b8c9d547c93f3566a53188d59ccaefa30d13c689029908570b7454997c406f4e74e4c80fec6b361d82a0ec648441e561b77ca8b9419ac873946d766f69e85248664570cc98385d0347b03a85701e2507530d94b464c83b244871725ee678aaf40dd330dba39a4c02896c6771bfe94330a094809db29a98cf2d867f48d5034423be54656637841f1d5cb5d1f280aaf43f85cf636bdb7b26b9e7f59a2bc4467a5f449484cb4c8218d05edbd98c897be9e11701367c43d450aa33006da97a3a4f02bb2827b6619ba776ea8dc23e28702860ae8596030db94629e24a2b788e6222baa1aabd99218ba7dd88072c6d00b1da552f80feaec3b422cb5eca81e933deae635135a070c39d41dd67682c2c5ab41c8ea84c287171d276a5b161f0158a9808531a1b3b7a7fd7a34b2950b21d92e0197b31598e7b2bcf770df902a1a2e14359152f2247a755371929019509992051afdb8292dc7d9c80cac6c7e68132a8b53f94e6b54e7cc2f2cb0d9e08cc58b0c6027ea445cad982fd630472386dedf3504e6a1a42629805be2ac3b99fedb236e99a650dac83062b62511de258f83c66e5618269b6e02ab2d9720f95778bc3d1e07de8707a9f47050754ded05d8c98b101714947a46453985017bf401a92ec0121d2e26034e46c710c2d7844c8c18012593b3f9cb902dc04346262627a3d53e0acdd8509a81b6c547058f68a062b94784199ce43155a24e43069c076b1c438cb7a20556136fbca7e40ef13e661358d4fc96b828569928ff832a41156fd67903e1206c6a9a74e73358113e06ba3a7e57f5a235e741c09cd39f823c4395e41605512fc17baf01779aaf0482643816fede45274b3ebd4caa2332509c420d2d99a0cdf189220a82c3e50077fd1b44cd61876992f208df8ab263b06f0572a95e"),
    ("v11", "09b8e950b419d5c40882d09091ea4579950fe1874a0ea03166609f205a08058737ef4afc2a4d222a438e29005c9d47d85080bce48bf030c2057260d8f9d762d19f8c29c6800bf5436648f153a63bbb404bd4b6cbdc5df15b70f416276ff9d38759148cb6a053c2c0ed324a4ed1b53d5ee81bdd546a679bb8a8d06e559d0847336149d32ad9935ad5e97b8024c79c8e015ae6dfef107e06859aa2af7a9a41daf65a025f9ee33235a21a1b9d38f9ea8e200f2df0b54f838e2951e2e224e94d3642f4c2d71e0038180b3bc2001c206cd76bb50500afbcb18a0a556288c1f31a4403e4bd31a0c3c3993344c288bb6bab76bce91b452e06c4a28d4a1b6c9f913e3eb88118ab471e342258e4cb841824e141c28ee38bc81d84e4998d5b78b2367b4b7db25971e9afca3798c16682cd203023d24b43b5c6dc490c05232a285876f8f186ecefe610910320e925de4d844742148102661e8be41255ad61684b56c45adc97ca43a589422b569c564703222d77791879eb04b5be2ccb77b65968b6b8f5c7b94b66905960dba029453f4c31bba8e3819335a0964309e3089db1096a43f47a04d0c95b245201fd3c555d6ea9542d98c35489da2f7084790b9cf66d982ad372dac01d6d8f17959a765b58b3e40e98b311c536b43f072860e86f774643df4fc00df4c92e7c8e9eef70ef2acd37d0b4f63fc8ff872a1e92e448698870fb23fc90008569f6e63f55927c2a5f892fcafc51a0a94506d61e2104baa91f64d369354f740341b31746dbd61bd6c0b1c15a38660de10b2da778db6a6f8f5a7ff4318ea18d162a457f28e6aa7880430c8c8dac8afbb99e0db938e8c5b4b303fc690d75f5b4dc4533de6495299c94097691db8240c29a0dba8272ede52bb5fd1435025841aa9822e583ee3959e8e5bf0ce3a86cc3421f2df934de54794b42d655c97a12aa4618515a53607fe66e1e09784849da329942af32a38c1aa4a46a68c101fdb4b518791a0cf02dd238e5465599026add9a1ad8a4b288f429902a25146e5e02f1ef492d64e12a834a903fb1dce68720ee21f6f3b0bc6e215fcd96e94fc330abfced84d001345baad6d5978f8b40598df497e935bdd049b5ff2f97592dc2e383998b4dc096b934d5de151c81938e5c8763ecf25814af888de1a719356c4546a5a835652f5c59e299c86c29606c794465eacadb2af27cd807c70895edae893b63912c24fa87ad20725a7a3bf47b4c3ca65546a2ad14287351f8104a0a93970044a98ecd7a"),
    ("v12", "097682303ad28afe68c1a34070530d858a1cf1cc62c962d29ca42613f0b24e867424579187929b11c1da90813e1b84c0c2e588bc427742c047116297d21de61f20541d661d67dfbbfefad0e005e642453bb4ff9f298950223b94eea4847e81c1241856b07532a25e5ea581e092537e2e2b93e4a6fb00504e44f44019226a32175a818149cd588786eb06ec83e714a6c94acec0804e60bd96cea633515e0f17b544ae217a42ea928d48652d6bd03f8999af8e69ba9ac0bcbe18c6a3904cc495d119fa33c847b3283604b56cb5734a5a56ad0b2e7b6e75c91eeb4e8be2c2345d551564cd035a6f8c4623e647200f28a79b305fa2bb173dbae0cab41d456c630e97248d03ab80eca17bb019611d989ba95607802c911a94e9d92fae3eda695d5036a872fca13b056e19c857a30d0a389e6916f367e690951431d4aec94d36bd3e6bb9e7a46a3a8a08e41868a42510e535e3de931053a8a362be3e058c554984d010011188c9e85b99ea266362d0775e36d6427a168f179a1fa21f8925ae5c405aae5f1c796e6eab7391422b9945c2291c35aa5899c20acd1502869106a38fb1550d7aa0dd5a7087ba267a77c859109e2105d2916a7f2876592d418fb0c4dfa6124a39a282b451e16905a6ccef79ead6e697b2e1c7ec04fd7515da2acbd6aa16ad931627990e60b925f67500a39850e64a6614896d5d4e604ba6ce4dc58bf72587d686f5dcfb6f2074b93debc85c001495d5a301f88c854f449950ef1e701e0977abd0d0986c8c65643d1b8e45f513377ba67d1ad82b16889d90acf41063531cf009f0db7556492773640bc7f5eada535aaa910a557f6198b7b15452b5615c8a553380a694c50a798851c345042b70335220b61a91947f6528b929c6c90802ee2c71d3a32521c574ac547212594e1649be10eb225f8766eac323dbf46c0644942a93ae781606cbc8064ebad2d75a7e0fa87b643789b956358e3161b9df565da40d808111d6bf52de8ba067520e79bdc15148c36784a5bb925a13781245e8c54d66680840c0539498340a1ae25a7b2c66054a999639eece72fe742b032ac744f15bc2a752a0804e537ad95bcf4740d5f2214f56ac1cb9a64a52892136d0e51d6b5387196f051526a96a86dba9f819ff2d191551671d119be15c767a869769419e0bcfac54a1b1896154a88e4bc2cf5bcd69a572adbb94626a712b5251812ac31d85e18dd6122aedb445f4873e2c7d352679971f66275440fd5663eb2ca16513f14e281c"),
    ("v13", "093074502968432030ed96f4cbdcb62914e061feca36be5e1a62b283bd50860a240ece28a21d27364a4b5939789b8acf894b96ea4b29776b8f674e90cac79b53a05afb546ed33a7886d7301895808aa0c8a0fa971f0188925740c6b84dcaec4655d050b51955d4e109e08462d2576801c467414aa763e096655169865ce8b2278da042cb2cc97c41ae17208f661cd17221a0cfc89ee253721698253b0d28d86115e4ba15c015935347802ec5b23e6cf0b199344416ca16a2110f9a6dec4b479273863d9da149ddf3d4481aeb17ec2c3009df963f9c0fd233cef645093ab406299570048717a9a627530d88cad899105bb1408588ae4e0f4a7ab424475f0da543e32e1fbd2bd1df37d712959e386885752bde72087b57f31354bdcd6d048291b99c1e36f24e835c11664717b5cc2574392964ef54c177659bcb326f1241ea0118b6e856aa92b2e5e212b2547e6519a8a6a59f20b25a11669e109076849b4e432f5e603360909d4cf2f54afd0a8bb89e8ebbb0a46389500763bb05feb2e5602345e7a17b8dc77a78cad4628d5eeafd5fb1064ed46a1e48f4a52e5c57aa2584986de3143fd4dbb67c7ff3b4a4b1899c8e9b4ea53428a52323d0123c1fbd3e0a5ecdd7a5cdd4e404c4fd9d7e3ec3e619ffbc08c7e392cd2d3a94b00b71dc2d2fdc79aa1d54f92e8573595d96828f5dbac9c4d7344b45a439d5ccd422482613f490b8bc513b838407ff91ce9879e32e37024ed62bf4ae8410510223ce09bc14c957db7a9cef929dcb3707a4913062d518f543e47b2200f948800f094451717bd5317804ec7795982917083fe703921cad2674d8801f8478298908d92a3b43616669eb5cd542ca8b218d6467adbcd2a7c4c71c410842b5a384a982a8be429bd215845141c22581f21d5d76da16eb4439746f50ed43d74a9ca3eb5715ce9e657eb4165775548df03a005a5d1eac94d8182b350b5639530c5581489ccf3bde44e610960fb2f02cd08632c796e26d85bd0dd82bf3e4534a56dad20956d144aeefb5044b957819c7d99812733014be2668a3837949ee87ee6ed01d34d3a4879ab53af4be006b5559803532714046aa4cdc35c938dd0eab4628f5b644357f01fc43daa4e935bdcbb4be6a381fd988b129c99e6fcc65a09617565a9e33c0d10b56a8669365b3671aa43cf79b8f288434058540f0d0676efe32f37da690769ec824e5d5783aa4c393fda8c64bfda427a5819eb00c92c091c7443ac2e224276fb430063070809a74"),
];

/// A13 legacy seat-key registry for `network_id`: 2300 → baked; other
/// networks → JSON object `{id: pk}` in the file named by env
/// `FPL_SEAT_KEYS_FILE` (devnets), else empty (the node binary then fills it
/// from the genesis `--validators` keys).
pub fn network_seat_keys(network_id: u32) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        for (id, pk) in TESTNET_2300_SEAT_KEYS {
            out.insert(id.to_string(), pk.trim().to_ascii_lowercase());
        }
        return out;
    }
    if let Ok(path) = std::env::var("FPL_SEAT_KEYS_FILE") {
        if let Ok(raw) = std::fs::read_to_string(path.trim()) {
            if let Ok(m) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(&raw) {
                for (id, pk) in m {
                    out.insert(id, pk.trim().to_ascii_lowercase());
                }
            }
        }
    }
    out
}

/// Admission key for `network_id` (env `FPL_ADMISSION_PUBKEY` on non-2300 only).
pub fn network_admission_pubkey(network_id: u32) -> String {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return ADMISSION_PUBKEY_2300.to_string();
    }
    std::env::var("FPL_ADMISSION_PUBKEY").unwrap_or_default().trim().to_string()
}

/// A6 proof-of-possession message for a new seat.
pub fn pop_message(network_id: u32, id: &str, bond_account: &str) -> String {
    format!("fpl-pop|{network_id}|{id}|{bond_account}")
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse::<u64>().ok())
}

/// `H_act` for `network_id` (`u64::MAX` = off).
pub fn network_rewards_v2_from_height(network_id: u32) -> u64 {
    resolve_from_height(network_id, env_u64("FPL_REWARDS_V2_FROM_HEIGHT"))
}

fn resolve_from_height(network_id: u32, env: Option<u64>) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_REWARDS_V2_FROM_HEIGHT;
    }
    env.unwrap_or(u64::MAX)
}

/// Presence rules on 2300. Tip was 424,639 when armed (9 Oct 2026).
/// About five hours of chain time later. Every seat must be on 2.9.63
/// before this height. Ignored from the environment on 2300, same as `H_act`.
pub const TESTNET_2300_PRESENCE_FROM_HEIGHT: u64 = 430_000;

/// From this height a Merkle batch body on network 2300 must still carry
/// each sender signature and public key. Receivers re-check them. Stripped
/// bodies below this height stay valid so the earlier testnet blocks still
/// catch up. Every seat has to be on a binary that keeps sender signatures
/// before this height.
pub const TESTNET_2300_MERKLE_SENDER_SIG_FROM_HEIGHT: u64 = 520_000;

/// First height that records a sender public key on the account. Earlier
/// blocks were sealed without that field in the state root. Writing it on
/// replay changes the root, so seats reject the block. 470000 is above the
/// stuck tip (468416) and below the sender-sig gate.
pub const TESTNET_2300_ACCOUNT_KEY_FROM_HEIGHT: u64 = 470_000;

/// v2.9.65 (audit C-1): from this height a tx may bind the first Falcon key of
/// an account only when the key is already committed to: the account id is
/// the classic address of the key, or a funder recorded the key hash with a
/// `PayToKey`. Before it, first-seen binding is unchanged.
pub const TESTNET_2300_KEY_BIND_FROM_HEIGHT: u64 = 571_000;

/// BRIDGE (one combined release): from this height the whole BitVM2 BTC
/// bridge + operator network is live at once:
/// - M1 attestations: BitVM2 attestations must be `Bitvm2AttestV2` (proof
///   bound to a consensus FPL checkpoint, fixed ceremony VK, Bitcoin peg-out
///   inclusion against the BTC rail); the BTC rail records FPL checkpoints.
/// - Operator network: `Operator*` txs (register + 5k FPL bond, heartbeat /
///   capacity advert, graph bind, unbond, slash on BTC Disprove evidence),
///   claim finality (`PaidOptimistic`) with payout credit, and the 5% operator
///   bucket carved off the top of every epoch emission.
/// - Testnet4 rail `BTC4` (created at this height, hard-coded checkpoint),
///   `Btc4PegIn` graph-bound mint, `RailWithdraw{BTC4}` BitVM2 claims.
/// Both change the commitment root once used. Height set by Scott 2026-10-20 (730k), moved to 692k (= Fix B) 2026-10-22
/// (testnet VK, docs/bridge/BRIDGE_INTEGRATION.md).
pub const TESTNET_2300_BRIDGE_FROM_HEIGHT: u64 = 692_000;

/// #118: from this height a non-enroll tx whose sender key is
/// missing from the in-memory key ring, but equals the key the account already
/// binds on chain (`meta.public_key`), has that key restored to the ring before
/// verify. Before it, verify is unchanged ("unknown key"). The ring is
/// node-local, so the restore changes block validity and must be activated on
/// every seat at once. Set in 2.9.73: tip 627050 at 2026-10-18T20:28:30Z,
/// measured 0.2140 blocks/s (4.67 s/block) over the prior 24 h, + 4 days,
/// rounded up → ~2026-10-22 21:45 UTC.
pub const TESTNET_2300_RING_RESTORE_FROM_HEIGHT: u64 = 702_000;

/// Ring-restore activation height (`u64::MAX` = never). Non-2300 networks may
/// set `FPL_RING_RESTORE_FROM_HEIGHT` (devnets / tests).
pub fn ring_restore_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_RING_RESTORE_FROM_HEIGHT;
    }
    env_u64("FPL_RING_RESTORE_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// 8980c0b: `Claim` binds a first-seen key (like `Pay`). Never released: no
/// seat runs it, and it changes which blocks a node accepts, so it is gated.
/// `u64::MAX` until Scott sets the height (all seats must carry it first).
pub const TESTNET_2300_CLAIM_ENROLL_FROM_HEIGHT: u64 = u64::MAX;

/// Claim-enroll activation height (`u64::MAX` = never). Non-2300 networks may
/// set `FPL_CLAIM_ENROLL_FROM_HEIGHT` (devnets / tests).
pub fn claim_enroll_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_CLAIM_ENROLL_FROM_HEIGHT;
    }
    env_u64("FPL_CLAIM_ENROLL_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// M1 is part of the combined bridge release: same height.
pub const TESTNET_2300_BITVM2_M1_FROM_HEIGHT: u64 = TESTNET_2300_BRIDGE_FROM_HEIGHT;

/// Bridge activation height for a network (`u64::MAX` = never). On 2300 the
/// environment is ignored. Other networks (devnets / tests) may set
/// `FPL_BRIDGE_FROM_HEIGHT` (legacy alias `FPL_BITVM2_M1_FROM_HEIGHT`).
pub fn bridge_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_BRIDGE_FROM_HEIGHT;
    }
    env_u64("FPL_BRIDGE_FROM_HEIGHT")
        .or_else(|| env_u64("FPL_BITVM2_M1_FROM_HEIGHT"))
        .unwrap_or(u64::MAX)
}

/// M1 activation height for a network (`u64::MAX` = never) = the bridge height.
pub fn bitvm2_m1_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_BITVM2_M1_FROM_HEIGHT;
    }
    bridge_from_height(network_id)
}

/// v2.9.77 (Fix B): from this height `key_bind_check`, `PayToKey`'s
/// "destination already has a key", and sender verification read only
/// on-chain keys (`meta.public_key` / `meta.key_commit` / classic address),
/// never the node-local key ring, so all seats agree. Changes block validity,
/// hence gated.
///
/// 2.9.79: brought forward from 702_000 to 692_000 (Scott). Set with tip
/// 673_438 (stalled, 22 Oct 2026 ~04:45 BST) at the measured ~11 blocks/min:
/// +18_562 blocks ≈ 28 h of chain time after the chain resumes. Every seat
/// (incl. outside operators nodesafe and crypto-dashboard) must run a build
/// carrying 692_000 before it: 2.9.77/2.9.78/2.9.79-beta.1 builds still say
/// 702_000 and disagree with this one on blocks 692_000..701_999.
/// The ring restore (#118) stays at 702_000 on purpose: it is in builds back to
/// 2.9.73, and from this height `onchain_verify_key` already covers its case.
/// Accounts whose key is only in some seats' rings (no `meta.public_key`, no
/// `key_commit`) must get a `PayToKey` commit; see the 2.9.79 release notes.
pub const TESTNET_2300_KEY_BIND_ONCHAIN_FROM_HEIGHT: u64 = 692_000;

/// On-chain-only key-bind activation height (`u64::MAX` = never). Non-2300
/// networks may set `FPL_KEY_BIND_ONCHAIN_FROM_HEIGHT` (devnets / tests).
pub fn key_bind_onchain_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_KEY_BIND_ONCHAIN_FROM_HEIGHT;
    }
    env_u64("FPL_KEY_BIND_ONCHAIN_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// Key-bind activation height for a network (`u64::MAX` = never).
pub fn key_bind_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        TESTNET_2300_KEY_BIND_FROM_HEIGHT
    } else {
        u64::MAX
    }
}

pub fn network_presence_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_PRESENCE_FROM_HEIGHT;
    }
    env_u64("FPL_PRESENCE_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// `E_v2` for `network_id`.
pub fn network_rewards_v2_epoch(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_REWARDS_V2_EPOCH;
    }
    env_u64("FPL_REWARDS_V2_EPOCH").unwrap_or(TESTNET_2300_REWARDS_V2_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unarmed_on_2300_and_env_ignored() {
        // No process-wide set_var: other tests build nodes concurrently.
        assert_eq!(resolve_from_height(2300, Some(5)), 420_000, "env ignored on 2300");
        assert_eq!(network_rewards_v2_epoch(2300), 9);
        assert_eq!(resolve_from_height(2200, Some(5)), 5);
        assert_eq!(resolve_from_height(2200, None), u64::MAX);
        assert_eq!(TESTNET_2300_REWARDS_V2_FROM_HEIGHT, 420_000, "armed");
        assert_eq!(TESTNET_2300_PRESENCE_FROM_HEIGHT, 430_000, "presence armed");
    }

    #[test]
    fn bridge_one_height_unarmed() {
        assert_eq!(TESTNET_2300_BRIDGE_FROM_HEIGHT, 692_000, "Scott 2026-10-22: bridge with Fix B at 692k");
        assert_eq!(TESTNET_2300_BITVM2_M1_FROM_HEIGHT, TESTNET_2300_BRIDGE_FROM_HEIGHT);
        assert_eq!(crate::operator_registry::TESTNET_2300_OPERATOR_REWARDS_FROM_HEIGHT, TESTNET_2300_BRIDGE_FROM_HEIGHT);
        assert_eq!(bridge_from_height(NETWORK_ID_PUBLIC_TESTNET_2300), 692_000);
        assert_eq!(bitvm2_m1_from_height(NETWORK_ID_PUBLIC_TESTNET_2300), 692_000);
    }

    #[test]
    fn splits_sum_to_100() {
        assert!(FEE_BURN_PCT + FEE_PROPOSER_PCT < 100);
        assert!(POT_PROPOSER_PCT + POT_VOTER_PCT < 100);
    }
}

/// Seat payout (validator rewards kept per seat, `SetSeatPayout` /
/// `ClaimSeat`). 2.9.80: same height as Fix B / the bridge (692_000), Scott
/// 2026-10-22. On ledger 692_000 the order is: time fold (settle at tip + 1 =
/// 692_000 already routes validator pays to seats) -> rv2 hook -> seat
/// migration -> txs (verified with the Fix B on-chain key rule). Changes
/// block validity and the root: every seat must run 2.9.80 before 692_000;
/// 2.9.79 seats disagree on the root of 692_000 onward.
pub const TESTNET_2300_SEAT_PAYOUT_FROM_HEIGHT: u64 = 692_000;

/// Seat payout activation height (`u64::MAX` = never). Non-2300 networks may
/// set `FPL_SEAT_PAYOUT_FROM_HEIGHT` (devnets / tests).
pub fn seat_payout_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_SEAT_PAYOUT_FROM_HEIGHT;
    }
    env_u64("FPL_SEAT_PAYOUT_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// Falcon PL 2.10.0 activation height on 2300 (Scott, 2026-10-28).
///
/// Chosen ~4 days out: tip was 733,611 at 2026-10-28 16:27 UTC and the chain
/// was making ~210-250 blocks/h (last 4 h avg ~223/h, slowing from ~314/h four
/// days earlier), so 755,000 is ~21,400 blocks away: about Sun 2026-11-01
/// 15:30 UTC at 225/h, Sun 19:56 at 215/h, Mon 2 Nov 03:24 at 200/h. Fastest
/// plausible rate (314/h) is still Sat 31 Oct 12:34 UTC.
///
/// Two consensus changes switch on at this height and nothing before it:
/// 1. `SetExternalAddrs` txs (`Account.external_addrs`). 2.9.81 seats cannot
///    decode the variant, so before this height it is refused at admission,
///    never kept/relayed/exported, and rejected at apply.
/// 2. Empty fallback blocks (a leader with no executable txs seals a block
///    with zero txs). 2.9.81 seats reject any empty ledger, so before this
///    height a 2.10.0 node refuses to seal one and refuses to accept one, and
///    the empty-block time-effects / proposer-credit rules are not applied.
///
/// Every seat and outside operator must run 2.10.0 before this height; a
/// 2.9.81 seat disagrees with 2.10.0 from the first empty block or the first
/// `SetExternalAddrs` after it.
pub const TESTNET_2300_V2_10_FROM_HEIGHT: u64 = 755_000;

/// `SetExternalAddrs` / `Account.external_addrs` activation (2300).
pub const TESTNET_2300_EXTERNAL_ADDRS_FROM_HEIGHT: u64 = TESTNET_2300_V2_10_FROM_HEIGHT;

/// Empty-fallback-block activation (2300).
pub const TESTNET_2300_EMPTY_BLOCK_FROM_HEIGHT: u64 = TESTNET_2300_V2_10_FROM_HEIGHT;

/// v2.10.1: BTC4 header fork fix activation (2300). Before it, 2.10.1 applies
/// BTC4 `RailHeader` txs exactly like 2.10.0.
pub const TESTNET_2300_BTC4_FORK_FIX_HEIGHT: u64 = 775_000;

/// Later-height BTC4 fork-slot replacement (2300). When both `btc_fork` and
/// `btc_fork_alt` are leftover earlier-height forks, a new main-ancestral fork
/// that starts above the alt tip replaces the alt slot even if its 1-header
/// work is not strictly greater (the leftover alt cannot be extended through
/// that later height). Replays the 2026-11-10 stall: leftover forks at 160182
/// blocked the canonical walk from ancestor 160185 ("BTC fork has less work
/// than the competing branch").
///
/// H = 860,000: above live tip 855,159 on 10 Nov 2026 21:15 GMT (~4.8k
/// blocks). All seats must run this binary before H; a 2.11.2 seat rejects
/// the header this rule accepts. Non-2300: `FPL_BTC4_FORK_SLOT_FROM_HEIGHT`.
pub const TESTNET_2300_BTC4_FORK_SLOT_HEIGHT: u64 = 860_000;

/// v2.10.3 (TBD): Hello minimum-release activation (2300). From this local tip
/// a peer must advertise `release_version >= HELLO_MIN_RELEASE`. Local only
/// (session admission), not consensus. **PLACEHOLDER / TBD**: `u64::MAX` = never.
pub const TESTNET_2300_HELLO_MIN_RELEASE_HEIGHT: u64 = u64::MAX;

/// Hello minimum-release activation (`u64::MAX` = never). Non-2300 networks
/// may set `FPL_HELLO_MIN_RELEASE_FROM_HEIGHT`.
pub fn hello_min_release_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_HELLO_MIN_RELEASE_HEIGHT;
    }
    env_u64("FPL_HELLO_MIN_RELEASE_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// **v2.10.4 single activation height** (testnet 2300). Every 2.10.4
/// consensus rule opens here together:
/// * BTC4 lend markets price per 1 BTC4 (1e8 sats) instead of the 1e6
///   fall-through (LendSetPrice / LendBorrow results change);
/// * `AssetPay` accepts BTC4;
/// * on-ledger order book: `PlaceLimitOrder` / `CancelOrder`, hybrid
///   book+AMM routing for `Swap` / `SwapRoute`, per-ledger expiry and
///   AMM-cross trigger hook.
///
/// **H = 800,000** (approved by Scott 2026-11-03). All seats must run 2.10.4
/// before H: 2.10.3 cannot decode the new tx kinds and computes a different
/// root from H on.
pub const TESTNET_2300_V2_10_4_FROM_HEIGHT: u64 = 800_000;

/// The one 2.10.4 activation height. 2300: the constant above. Other
/// networks: `FPL_V2_10_4_FROM_HEIGHT`, else `default_other`.
pub fn v2_10_4_from_height_or(network_id: u32, default_other: u64) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_V2_10_4_FROM_HEIGHT;
    }
    env_u64("FPL_V2_10_4_FROM_HEIGHT").unwrap_or(default_other)
}

/// 2.10.4 height with `never` as the non-2300 default.
pub fn v2_10_4_from_height(network_id: u32) -> u64 {
    v2_10_4_from_height_or(network_id, u64::MAX)
}

/// Legacy alias kept for the lend-scale code/tests (= [`TESTNET_2300_V2_10_4_FROM_HEIGHT`]).
pub const TESTNET_2300_BTC4_LEND_SCALE_HEIGHT: u64 = TESTNET_2300_V2_10_4_FROM_HEIGHT;

/// BTC4 lend-scale activation = the 2.10.4 height. Non-2300 networks may
/// still use `FPL_BTC4_LEND_SCALE_FROM_HEIGHT` (tests/devnets).
pub fn btc4_lend_scale_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_V2_10_4_FROM_HEIGHT;
    }
    env_u64("FPL_BTC4_LEND_SCALE_FROM_HEIGHT")
        .or_else(|| env_u64("FPL_V2_10_4_FROM_HEIGHT"))
        .unwrap_or(u64::MAX)
}

/// Order book activation = the 2.10.4 height (non-2300: env, else never).
pub fn orderbook_from_height(network_id: u32) -> u64 {
    v2_10_4_from_height(network_id)
}

/// BTC4 fork-fix activation height (`u64::MAX` = never). Non-2300 networks may
/// set `FPL_BTC4_FORK_FIX_FROM_HEIGHT` (devnets / tests).
pub fn btc4_fork_fix_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_BTC4_FORK_FIX_HEIGHT;
    }
    env_u64("FPL_BTC4_FORK_FIX_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// Later-height BTC4 fork-slot replacement (`u64::MAX` = never). Non-2300
/// networks may set `FPL_BTC4_FORK_SLOT_FROM_HEIGHT` (devnets / tests).
pub fn btc4_fork_slot_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_BTC4_FORK_SLOT_HEIGHT;
    }
    env_u64("FPL_BTC4_FORK_SLOT_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// External-address activation height (`u64::MAX` = never). Non-2300 networks
/// may set `FPL_EXTERNAL_ADDRS_FROM_HEIGHT` (devnets / tests).
pub fn external_addrs_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_EXTERNAL_ADDRS_FROM_HEIGHT;
    }
    env_u64("FPL_EXTERNAL_ADDRS_FROM_HEIGHT").unwrap_or(u64::MAX)
}

/// Empty-fallback-block activation height (`u64::MAX` = never). Non-2300
/// networks may set `FPL_EMPTY_BLOCK_FROM_HEIGHT` (devnets / tests).
pub fn empty_block_from_height(network_id: u32) -> u64 {
    if network_id == NETWORK_ID_PUBLIC_TESTNET_2300 {
        return TESTNET_2300_EMPTY_BLOCK_FROM_HEIGHT;
    }
    env_u64("FPL_EMPTY_BLOCK_FROM_HEIGHT").unwrap_or(u64::MAX)
}
