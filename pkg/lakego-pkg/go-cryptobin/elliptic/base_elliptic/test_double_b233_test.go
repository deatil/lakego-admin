package base_elliptic

import (
    "math/big"
    "testing"
)

func Test_double_B233(t *testing.T) {
    x, y := new(big.Int), new(big.Int)
    for idx, tc := range testCase_B233_Double {
        double(x, y, tc.x1, tc.y1, b233)
        if x.Cmp(tc.x) != 0 || y.Cmp(tc.y) != 0 {
            t.Errorf("%d: wrong x,y", idx)
            return
        }
    }
}

var testCase_B233_Double = []internalTestcase{
    {
        x1: HI(`0106d6eb5aa30b22130fc176da5cbf31e21da5a5a903ff4bc340fbbadeb8`),
        y1: HI(`b9b7253270795df2a2f415e7f4e6511f3e8668da8f95b8361f6f605f65`),
        x:  HI(`6b07b6ce1e66f3854116f05d9131dfecf399600c19d2a52683167e55b5`),
        y:  HI(`0143d90b9c860d8bc974bde2d175de4ec2830c96717bf59a057fafad9ab2`),
    },
    {
        x1: HI(`0188095ee968b90a30d4cc8a89d24830da2cab24eb2c8ed40025f084c1d2`),
        y1: HI(`9045c9f33b46f621d74babf883a84dc0e119a5e3b9dcfaae63c23740b8`),
        x:  HI(`7952f27087e3153d557c9a7b43ed1b3ec5f380cd2153c0405793194b57`),
        y:  HI(`01ef6e2aa66aa7244c63596c5349373f6401383cf74ae5c325600df90390`),
    },
    {
        x1: HI(`01b693d2db14af541516b87fe537ce4f39324fdd0113debc7b66fba77d06`),
        y1: HI(`017bef5306de3ffa55e16d2311b4f5946252297ea89b22de53002096f190`),
        x:  HI(`01643c8946616b0f71978b313c290aa8c56de45279330c4d32acb9fb50e2`),
        y:  HI(`b35a453d8c1e87c40482b208c47a658009bca200dc51abd7e5d1ff3d32`),
    },
    {
        x1: HI(`01a5ea9b569361834711defe0691b1efd7dcc3e88f1d48f1cf527176bb04`),
        y1: HI(`015ecbf01e16824072eff63e3328423e1cf2ebc8f3d48c247271dfc82b09`),
        x:  HI(`cafcf6849512c6152409a4501b9ecc36e1b27e4ac2372d383bf07c76e3`),
        y:  HI(`e9f15636f24eae6b95b2bd8af2517d98313f3cabab675e10f4ebe89f5b`),
    },
    {
        x1: HI(`2586e9e466686bfe330c7494d6dd72ee7196c3b5dd380d8884a83a2fd3`),
        y1: HI(`014cfce6b7713172b411636d6f0e32c60a0b33ca1ef32848306292cf7580`),
        x:  HI(`8ba82751dfe9772407e0f4c5c179b8cecd383043908d7cd8f64b2d23c6`),
        y:  HI(`a6cf6dcee6f095384432c7efd962974a2f60719d5220fc30270273456a`),
    },
    {
        x1: HI(`5062d7012db19aba9b60bcbb2da5fac434dac4d33dcecd722c55eb86e1`),
        y1: HI(`783f51b69c6df1c6a8c3e7d94faed46cdd703074e6330028571007c279`),
        x:  HI(`e713c3fca276973dbe1bc5c4ffe610e6f384b386830d17aea60b1ba413`),
        y:  HI(`04dd69a2df714235c132194aaa7765f2950570e5241fa1716f7c39ea36`),
    },
    {
        x1: HI(`12cf0ea2719a91590304d8eed1b8493cea6229fabb590e8221769e9827`),
        y1: HI(`016869b1fb11668f21ca53c86cd113f2cff8f9f2d0968bfc7e984c825229`),
        x:  HI(`9f216e387d5ef7cbfd148b4c203f19b3763f8b4bef1dc6d7bac58449a1`),
        y:  HI(`bbb884982ccf82839f5699d4f3d467d5b7dd444882e567d3bd2721af29`),
    },
    {
        x1: HI(`68219cce451271d53ec9af6f6cf418d0986fc814a5e73fdfec8913c930`),
        y1: HI(`018334579ee32e77aa80011d3fcd2c60b770ead0398b94800fc9c218b199`),
        x:  HI(`01b4af09a0b122d2a4dacb9815f8f096775e9e520534515a2dfe3b8208e0`),
        y:  HI(`8eca5a07933a412913efe820da7af1379268e076b04c8863e6802de726`),
    },
    {
        x1: HI(`01ecf281d63d429ba6ea80f0f64a434940c5062f696d7eb27da7eee5697e`),
        y1: HI(`0b158d7ba3ce2e53c1983ce70df99301693bce48f1444a5ba8d542c1a8`),
        x:  HI(`c4ec01d324b7b08007c1ad5c5d5b8305052968ca8739a3f2cc5935eae6`),
        y:  HI(`01e153d8041f1c927bdb186403c62434c253bb99cbfabeb7c98f80f18159`),
    },
    {
        x1: HI(`a30d16e347ccd534134aa97df6b024844eb7b95349da7a2eecfd857405`),
        y1: HI(`013fda62f385b79e508670a0914da0829f279944f4c1afeb312f3e477d3e`),
        x:  HI(`01de9f3240cfc2ec843040431124bf6eee18d79e057a4f9799b04b060b0f`),
        y:  HI(`013e8c3fc34ae82fb26d69232251412799db0ff0fa57b7cfe9ffce591043`),
    },
    {
        x1: HI(`012ed6bf31c13bb522d4e3e15616b474d4ab214ddc7e35dc25c867737fde`),
        y1: HI(`c61a06cd977c5bd04893538c0315ed5b305d21e64805dcc2ff7d027abe`),
        x:  HI(`016b391a59cf2a4632d12db57fe69597d2b49ffb62f2fcc88e506b3a8687`),
        y:  HI(`01e2d6de85d86b58c93b3eec7cc91be07a0b11c86791b410c73e65cf91f5`),
    },
    {
        x1: HI(`01624b0c8cb8e219bd3214d0ada08a1e29323cf401141e760d282207cef7`),
        y1: HI(`c11ff1378ffc40eb434aaa5dda1dc2e62a2889f752b1a05a078328f210`),
        x:  HI(`01d82862cbd307e5f0bb22d81e99d8b742f004036e9d20317e2c3800f519`),
        y:  HI(`012934936ca40ee819b595bd431b5a8fe836c4b7f05c8e6e6b766114bfb9`),
    },
    {
        x1: HI(`01fb4ec11f8d0fe522bea7af35819ce1181a99aa8c4793303574e5e0169e`),
        y1: HI(`ae5c79c2c3f6c4180daa370341e73d476428aa14ed52fbe9fc92af5bb3`),
        x:  HI(`0444f896bcf50cca3680cc36879c0965e5b4b06f505d652fad18ce6da8`),
        y:  HI(`0175b4c192768989fe219d5fdbcb02fb6672188cdf442726445941ce0554`),
    },
    {
        x1: HI(`125dfdb7c5ee088ac5d9108ece15557c7bea6903d734f2b2e0fa542b4e`),
        y1: HI(`ff22492f2ef876feeb67f506937d3a17bea61806ffb8e1fde774cdb697`),
        x:  HI(`017fe2c0548c2c9c87bda3c0d5f95159ea8d6e6f4391efd0d1fa17e16d02`),
        y:  HI(`b6407ed0fca60fee965e23f8d442f1162422e1c27bd8260f09ed00cde3`),
    },
    {
        x1: HI(`0bb1105b58acc389814633cda990b54e05a9bb333ed5321fc05e97a5dd`),
        y1: HI(`010af1c667e1326a7a1790e04fa6f88ee5eb34081fabd5452c5b9b9d49a9`),
        x:  HI(`524098ba6950fb635483d1b0d91bb61ba843cac01aa03b38add7da5038`),
        y:  HI(`019b0c1d63c1d1114f455cc5619cbcaf8cd5ec81712a9043b6c7b2c5ae1e`),
    },
    {
        x1: HI(`7371c8a9eb6ca9731700fd887111013cb3192eddc5cb18efe0cc427ebf`),
        y1: HI(`d715d386985cd001fcd293d375c0e61169f2719de6e71d54069f385501`),
        x:  HI(`01d7becc95a10d865eb03ebb2648a6eb17da5c91ba0d52d5c967eb03cfc1`),
        y:  HI(`0121ddc6259339bde989e7e162774ec599f2a938857167f8af6fb404e1f1`),
    },
    {
        x1: HI(`34d1a270f5df09b90aeb9362c0f15470bd1b7f788e983d25bbc787c2fa`),
        y1: HI(`01a21158e5df9e5af130b7376a894970628417b860f2db3514d8ab8295ef`),
        x:  HI(`011db2c7fb2dc41cb82afaf0df576e2918413fb90c0513310c06e1fa25f0`),
        y:  HI(`4beb04046e7e607a6b28db26590e6df4fa7dedd60a21c5e5276289c00e`),
    },
    {
        x1: HI(`01974f7b608fe62dc7d279e061a0d5ac9118962042cbffc9112904b30bd5`),
        y1: HI(`466154c6c5d1ac90f82f796c0fd11f4bc94475db5b3229ac96b5d010b5`),
        x:  HI(`01e4faaaa95ab44d52b1d084b27cb108402bc38fb3e834755ad559f1508c`),
        y:  HI(`61fee6092bae5b665d4ce5e30fe65824ae99ac8ce6fb0051c4598c77ad`),
    },
    {
        x1: HI(`01a3aef4a879db97971fcc24f0eb19aef382856ecc4098ed78c9131c3114`),
        y1: HI(`0126b1eb3831b9be35387728a9472ddb8003bcb2dc931b652bd7ce76184e`),
        x:  HI(`71562c8b0163e49547d5a222c6ebe8463f82e738169cc1ce94d7dae3f4`),
        y:  HI(`f4f0ce9d5a859fcf7f4bec40c9061cf939ca6f4c788c84f595a283e676`),
    },
    {
        x1: HI(`3a88da03bc80c64ec520bd81b45b3cc52529d7e9778291868fc1e77471`),
        y1: HI(`a2ac89e54dc3561b4fbe6fd270a302e6517bb658e5bac18025dcb4f267`),
        x:  HI(`01109163c18acb8e26543e600a46b802c7eb3d84a0257c3238a227f5b2cb`),
        y:  HI(`0113c03cc10783548f47afe58cdffe199b0506c8f247da74321f63e56f2f`),
    },
    {
        x1: HI(`635c023e8ebf4aaa7ab614d8a7b17400310731a853f521ce22b444c86e`),
        y1: HI(`01aa426e9dc389b691d00f6120bce40ba7bf984f8369084e7d086e9396df`),
        x:  HI(`b4831a6b2980c735f81adb3f530a424cb9f7df07b9327126342675a3eb`),
        y:  HI(`dc3e499ea60666bafb801ae5e7dd3780a99c38e93225b4d21b0a1dc0a7`),
    },
    {
        x1: HI(`d0c9347de6c1fb29aa2bf9b6af7372c76b07103ad928e311b011c69265`),
        y1: HI(`6980211826cd8b39ebccd94e0132e535b85ee3657576914da0bcb0271e`),
        x:  HI(`990ff85e8e442d4f03cf28386304544ec85143e838459f9881410f1214`),
        y:  HI(`816177c99a258b97a16bfaf19264d1d070125fe66925d974c85aa6ca9a`),
    },
    {
        x1: HI(`017024878566bd46b998df594add6f326bc8e9ed4d36ac4747f44fb8139a`),
        y1: HI(`019a62cc11f3a91c0edeee34acd2f201202c8a875fbc8287cb2865bf8413`),
        x:  HI(`0142d5aebf96de3700b4412ba54ce7e9d46e4ffaa1475c3ad57db51994cf`),
        y:  HI(`01e4bf574b3c3d90d891921b5960bd4f6f5e218406c7718c288edfb94b29`),
    },
    {
        x1: HI(`16af0b53fd412709be9c903fd2f088b711c65c4783409f4f64c0a4c838`),
        y1: HI(`01b1a5480cf99f2a7fcd90bef76e816cd733ab9658e3b259d964ff9dc08e`),
        x:  HI(`013b45a5434359ee3b242467edbd70e766ce870b25ea2b60ee2865cffa9f`),
        y:  HI(`15e7631f9a53b1ac5f2ab98c01923097498041336098fe3f282c5d944f`),
    },
    {
        x1: HI(`013dd1ed2936441434a50bba84c7507d327b9f14577e707ce7898d2afff5`),
        y1: HI(`01bf572552dca3e592ea043cd1350c74b147cf05f1e9b3ceaa5d22932ddd`),
        x:  HI(`014cb71cf593d071371ca6466572436d9f28183dcee6c7b5bef6e995732e`),
        y:  HI(`01eac3544530f808a72e1ed65204b6df46c391f6edd4ab0569b7a7a79b46`),
    },
    {
        x1: HI(`0646cfb97315c48be392b63cb13958e4ed89e195252164a9a68f907384`),
        y1: HI(`01b34eea654dbc04d2b6b69b2d83f77eee7c53e202e530fbb20942c65880`),
        x:  HI(`017200b77ceba06faa00b019c0fa1c402cec69b0f70c7411b45c95537676`),
        y:  HI(`01a86933ad01096a236fb94b6a4b9726a1f5463bae7b482cd945d6ac24e6`),
    },
    {
        x1: HI(`1201d4ca67a06418168f6ae800d50c3f49f22b5ea084e9aea814b29064`),
        y1: HI(`01a0968010a22b623cbf7b461b77b7c00991da4efb36b138a0d7b26ba9a7`),
        x:  HI(`325b7c63d8e60f06d92f7c6ab46da381661b3e2d1b9d6b49d9d70985e5`),
        y:  HI(`011563f62b62a6f0172a2dc56a05f36104766ae7fbb2049d0d207d19779d`),
    },
    {
        x1: HI(`019f787ff6b013490877fa501dc8cedd0d6be106d0a793a05379ca6dce4a`),
        y1: HI(`c9f8ac11da58daae65da983f2baed05569e027276effa7d761077fbfb0`),
        x:  HI(`0115b5da41734f8c25043f5e965272eb842d519044e235b6f754a75fc3d7`),
        y:  HI(`011ef49084c0af71c294d888ed0d25ea9462c2a89c8a9803426b10d66db7`),
    },
    {
        x1: HI(`01781b25ec1ca8df92bbab95f7433822b7a0e56ee53ef7602a145664a44e`),
        y1: HI(`e0204e1cbdad24e430ec2b865df001add24d9dcc061b0ba229b793f92b`),
        x:  HI(`ef695819e6b2b36660278a99e5503fc7951072cab701f766f0143a1bb3`),
        y:  HI(`01d23b1d84e814749a22220bc90ea5de192a15dba7ac014600b4b8410f2f`),
    },
    {
        x1: HI(`0116ae3306cc298250287191d90e314c8c9a68462d7f3c9cb55bbf177321`),
        y1: HI(`d894616acb321bf058db05a581b92bc8c26e191b3aa8653870201a348d`),
        x:  HI(`55462578ffaba3d0569faa227cdefc06c8ae085612894857de8b2d801e`),
        y:  HI(`b3f03a14d1a9274922114a525d616c58f2d965ccf94b816709a931aa4d`),
    },
    {
        x1: HI(`e1368c09844fed8d6edd68e1d2be2af4a0d29aad42b7ce9db343805670`),
        y1: HI(`017e1d9cfe0787d6a28fa7877b34a09e74665a61216255250cb81cf3ad70`),
        x:  HI(`01765ed3a290b3d7db88574f2a257a8ff52fa653c14ac027d38939fa247b`),
        y:  HI(`015f19c2f7006a5cf08b62b9f4931ec61f277c60a0426f7f7ced61623a4c`),
    },
    {
        x1: HI(`011176cd9614fbaba25ec98a924b5b101f416334c275c268187651d61cfc`),
        y1: HI(`01fc0bc49cd798bf1221549c8b0b4eb94bb94013e47c773fd3ac7893d0a1`),
        x:  HI(`ac345d2330b3f53f8f6682d472e6744bb9e244766b60ac6913ee885c21`),
        y:  HI(`011e2d1355acff0451eb2eade60561a05b5ec3f16e0d592a26b1ebe60b86`),
    },
}
