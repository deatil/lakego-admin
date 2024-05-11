package luffa

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    msg []byte
    md []byte
}

func Test_Hash224_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("616263"),
           fromHex("f29311b87e9e40de7699be23fbeb5a47cb16ea4f5556d47ca40c12ad"),
        },
        {
           fromHex(""),
           fromHex("dbb8665871f4154d3e4396aefbba417cb7837dd683c332ba6be87e02"),
        },
        {
           fromHex("cc"),
           fromHex("e47d4158bfe03555d370d8fd877ead17d6aa9fdc689a9614c411fbba"),
        },
        {
           fromHex("41fb"),
           fromHex("08cbdd1c9caea9711ab2b30b872ddc09f2954b98ac1850abe3f648f1"),
        },
        {
           fromHex("1F877C"),
           fromHex("a590d4995c909abd9150398d4ab9465a8e9f768c576921c26a998857"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("25c82f898f66355aba7a6215d07cab27fbeeedd16b52aa910040b40f"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2ae8ccefd8eb75d7767d4db991a6dd36e7d39a35e54a9e205c074d0e"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("72467235c784fbc2d31d0743bf9ef68b0b3a56ae7e2be95f56a2837a"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("383121b1c9e7e2d0e0b0bd63caf89ea25bcfe6092e9e90215c1fd2b7"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("a65984fe81e98324c070151b1d726f74c15bd1587732185bdcdec716"),
        },
        {
           fromHex("512a6d292e67ecb2fe486bfe92660953a75484ff4c4f2eca2b0af0edcdd4339c6b2ee4e542"),
           fromHex("4e093b0251214d672f1e30093271a269c0c7042a714b6cdb4733ec7d"),
        },
        {
           fromHex("36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05"),
           fromHex("bc5d5ffd0ae42b04b91fb9bd5c868387a61c9466b1197f8c1cd7bee3"),
        },
        {
           fromHex("abc87763cae1ca98bd8c5b82caba54ac83286f87e9610128ae4de68ac95df5e329c360717bd349f26b872528492ca7c94c2c1e1ef56b74dbb65c2ac351981fdb31d06c77a4"),
           fromHex("5fbbe4a62e2b3aefc627334a256768c89ffc67971aed49c53c0f0afa"),
        },
        {
           fromHex("94f7ca8e1a54234c6d53cc734bb3d3150c8ba8c5f880eab8d25fed13793a9701ebe320509286fd8e422e931d99c98da4df7e70ae447bab8cffd92382d8a77760a259fc4fbd72"),
           fromHex("8335c00f01f81fdee0586da33d78d0e8099a64e439ee0df192000450"),
        },
    }

    h := New224()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New224 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum224(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum224 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash256_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex("616263"),
           fromHex("f29311b87e9e40de7699be23fbeb5a47cb16ea4f5556d47ca40c12ad764a73bd"),
        },
        {
           fromHex(""),
           fromHex("dbb8665871f4154d3e4396aefbba417cb7837dd683c332ba6be87e02a2712d6f"),
        },
        {
           fromHex("cc"),
           fromHex("e47d4158bfe03555d370d8fd877ead17d6aa9fdc689a9614c411fbba370c1706"),
        },
        {
           fromHex("41fb"),
           fromHex("08cbdd1c9caea9711ab2b30b872ddc09f2954b98ac1850abe3f648f11b76bf92"),
        },
        {
           fromHex("1F877C"),
           fromHex("a590d4995c909abd9150398d4ab9465a8e9f768c576921c26a998857e7b0a604"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("25c82f898f66355aba7a6215d07cab27fbeeedd16b52aa910040b40fda859981"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2ae8ccefd8eb75d7767d4db991a6dd36e7d39a35e54a9e205c074d0e28cb9885"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("72467235c784fbc2d31d0743bf9ef68b0b3a56ae7e2be95f56a2837a6067fefc"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("383121b1c9e7e2d0e0b0bd63caf89ea25bcfe6092e9e90215c1fd2b7ee8bfb45"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("a65984fe81e98324c070151b1d726f74c15bd1587732185bdcdec716cdec4767"),
        },
        {
           fromHex("84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29"),
           fromHex("e0d34790dd95f336c67172070982b61f715d2ce3f8d5afb95e003f89fdf8c888"),
        },
        {
           fromHex("47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492"),
           fromHex("03b3a5833e3ea623dd274c2695ea096100dfa4252a602368bbd41fde3f05761a"),
        },
        {
           fromHex("7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3"),
           fromHex("addd4250956d57d8320bbdaa6c8b230dc428ebf559d837bdc3b27e531dbed955"),
        },
        {
           fromHex("36f9f0a65f2ca498d739b944d6eff3da5ebba57e7d9c41598a2b0e4380f3cf4b479ec2348d015ffe6256273511154afcf3b4b4bf09d6c4744fdd0f62d75079d440706b05"),
           fromHex("bc5d5ffd0ae42b04b91fb9bd5c868387a61c9466b1197f8c1cd7bee3666b5ec6"),
        },
    }

    h := New256()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New256 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum256(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum256 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash384_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("117d3ad49024dfe2994f4e335c9b330b48c537a13a9b7fa465938e1a02ff862bcdf33838bc0f371b045d26952d3ea0c5"),
        },
        {
           fromHex("cc"),
           fromHex("e1979d16848976ca9ff183ec28998ab3d4b56942497f8e2c6d51895a96c7465df6d7b66d6ba9636a16dbe51aae6d2eb9"),
        },
        {
           fromHex("41fb"),
           fromHex("836e9c8429d4a071935c72b0e575ea4cca81642dc14a98a87307e02ac2d812682ce3eeaf8043330a7ea5cbe3a578b5d2"),
        },
        {
           fromHex("1F877C"),
           fromHex("0aff61867c087908d2b9742012bb980cae833c79fd4ecaaea31bc1279f4ce356d6308c36d1fd0dbe70f652b0e2c66d35"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("3736466ca7dc43a81025378e6ce678fe010ebb06382a73113af39104cea0f9bf00e27d12e0a1e7f37516e5cd0f2e9752"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("7772a0c884ee0b24eddd7d863db7d28a0902268054eb4098539881c0530473a8a6d5ad4ab0168c58dc6788d31a65e3f9"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("3f799bc392ca79e7a7d71a3fdb513b86eb871bd3c718c1ce7091c88e431208c76a94aeeecb822cfc7b71876ed83bc98c"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("2bca547654d4ad268e8e080b5484d6607876dff50c1021c855bfe48ca9ce51cfe0f79f671c61c4c43622c1d704270079"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("112293cc150e8b5b040c4f07c561a90e1afdf21b0dda7577c75f2f0adae3da1170573250fab5cabe28349b693cd70ee8"),
        },
        {
           fromHex("84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29"),
           fromHex("949451902c0a00fc04a97a8d59bef41c4f39645b6f3f80b8b6ed5c6a2b615fef61f17577394756d6262e25bafd0c13b7"),
        },
        {
           fromHex("47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492"),
           fromHex("27fb306fd7e0ae1fa8122835df37db90f0c9f1869a32cd10dd21bb380dbe88623683d88bc48422f2ede44c53bdda1f4a"),
        },
        {
           fromHex("7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3"),
           fromHex("52769b8dbb7dccf0835e1cf5dbd2aadfe9c3a1d737d5ea366a82afc799224fc8aa80c7dda3996fdac2e19bd5d12035ec"),
        },
        {
           fromHex("95d1474a5aab5d2422aca6e481187833a6212bd2d0f91451a67dd786dfc91dfed51b35f47e1deb8a8ab4b9cb67b70179cc26f553ae7b569969ce151b8d"),
           fromHex("dc51485e19cd24f7588414b5cd26d52ab0c149663c7fc3ab19e00186aa733f2d1269d8b3e82f0a8c678f24e10703e5b0"),
        },
    }

    h := New384()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New384 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum384(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum384 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}

func Test_Hash512_Check(t *testing.T) {
   tests := []testData{
        {
           fromHex(""),
           fromHex("6e7de4501189b3ca58f3ac114916654bbcd4922024b4cc1cd764acfe8ab4b7805df133eab345ffdb1c414564c924f48e0a301824e2ac4c34bd4efde2e43da90e"),
        },
        {
           fromHex("cc"),
           fromHex("91f1b09b2842871bc2f069e5d278d2d707ddafabfe3ced5154faf841e96781908290e6533d146183e8b7ec298f6da20e0cfb1d41f4f711a3050faa8dd4641f7f"),
        },
        {
           fromHex("41fb"),
           fromHex("3448d8766e1c8cf84ca83d0882305a8ebcab3f9c5b87f8f1bb94ec8abbe86320e6d33024fbe9363595ed3b36bf49a5440a1248f0606940aec1321fc74dbb6be5"),
        },
        {
           fromHex("1F877C"),
           fromHex("327ed73e847b90a1d098250020e45915ce4991b686e3920043ab17f026b2d3c77f9fed996673d527e4a1f628fb2f4f05949d3eabb0b00d9967063877e4370015"),
        },
        {
           fromHex("c1ecfdfc"),
           fromHex("d6c06a024d386a58a01d9c5852229593f2197bd9f3afc9eb3f3230807d99c06d8eeb7aa36d7eea74fda69ec1356191985cadedb24bf0c312ba1db9e974442b16"),
        },
        {
           fromHex("1f66ab4185ed9b6375"),
           fromHex("2d0288e2090f0d306a033c96c2d17d6cf6d9803d682e01f40c83890156e872152a24dd26a9812b2b7bdbb31670d22a2f8c492e592ed5c2a9076ebb2a55014772"),
        },
        {
           fromHex("a746273228122f381c3b46e4f1"),
           fromHex("e8955edd828e3bf0db896e394aefc9ca7ee0e39622ca7649023506500d2d673fcbb1ba341ca35713ff1f07d45c2503b966ddef23ec5a4e8bce61f1dd0492e32d"),
        },
        {
           fromHex("d8dc8fdefbdce9d44e4cbafe78447bae3b5436102a"),
           fromHex("730fff7f3a49b3602b9d242363b8e5a34864c4c20c0d432ac2bbfdf7a6d37646218827e541c600f3e50b45757058a69a89b6f011190247ad6f3c3b3df856a93e"),
        },
        {
           fromHex("aecbb02759f7433d6fcb06963c74061cd83b5b3ffa6f13c6"),
           fromHex("78ad8a9b487907c61ff260707b31f743ff1b5dfbb812649d096cc619930d2010b9496f299d0bc36e5962f53a085a8981a9ce624d4624bd782c8269fbd994b236"),
        },
        {
           fromHex("84fb51b517df6c5accb5d022f8f28da09b10232d42320ffc32dbecc3835b29"),
           fromHex("8c423ef68e6ebc93711884e2ce53c5dfdb9e4ce52fdce4c11143985f204df2949e15c908a14e807aaa409f90a0c0fefbb7436af034339f9d9f229a9c5de05b43"),
        },
        {
           fromHex("47f5697ac8c31409c0868827347a613a3562041c633cf1f1f86865a576e02835ed2c2492"),
           fromHex("1726be6a7b9fca0a43e6350272631eaf24119ef7f8acce8b3489e46fb68ef5623dce5b3473c062fe5414d8462477efd10dd4526cfb70b67116ba4d2859fbe5ea"),
        },
        {
           fromHex("7abaa12ec2a7347674e444140ae0fb659d08e1c66decd8d6eae925fa451d65f3c0308e29446b8ed3"),
           fromHex("c1ecf8daff34596ba651cf9034495bfd277409dfac5360d9149ab1bade8c2d1174368960454d8b1183ab141f36dc71f8722b318de37644b75db098cf69070999"),
        },
        {
           fromHex("e926ae8b0af6e53176dbffcc2a6b88c6bd765f939d3d178a9bde9ef3aa131c61e31c1e42cdfaf4b4dcde579a37e150efbef5555b4c1cb40439d835a724e2fae7"),
           fromHex("e18b08234bed8586b8d40314dc2854086d8d85ddf83b321800b4039bf162fc4ab9229ca3d34f5c554e8409ef70a50c13164d00094142a6139b36e3ab911c81de"),
        },
    }

    h := New512()

    for i, test := range tests {
        h.Reset()
        h.Write(test.msg)
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.md) {
            t.Errorf("[%d] New512 fail, got %x, want %x", i, sum, test.md)
        }

        // =====

        sum2 := Sum512(test.msg)

        if !bytes.Equal(sum2[:], test.md) {
            t.Errorf("[%d] Sum512 fail, got %x, want %x", i, sum2, test.md)
        }
    }
}
