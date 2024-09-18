package bash

var bash_rc = [BASH_ROUNDS]uint64{
    0x3bf5080ac8ba94b1,
    0xc1d1659c1bbd92f6,
    0x60e8b2ce0ddec97b,
    0xec5fb8fe790fbc13,
    0xaa043de6436706a7,
    0x8929ff6a5e535bfd,
    0x98bf1e2c50c97550,
    0x4c5f8f162864baa8,
    0x262fc78b14325d54,
    0x1317e3c58a192eaa,
    0x098bf1e2c50c9755,
    0xd8ee19681d669304,
    0x6c770cb40eb34982,
    0x363b865a0759a4c1,
    0xc73622b47c4c0ace,
    0x639b115a3e260567,
    0xede6693460f3da1d,
    0xaad8d5034f9935a0,
    0x556c6a81a7cc9ad0,
    0x2ab63540d3e64d68,
    0x155b1aa069f326b4,
    0x0aad8d5034f9935a,
    0x0556c6a81a7cc9ad,
    0xde8082cd72debc78,
}

var bash_rot = [BASH_ROT_ROUNDS][BASH_ROT_IDX]byte{
    {  8, 53, 14,  1 },
    { 56, 51, 34,  7 },
    {  8, 37, 46, 49 },
    { 56,  3,  2, 23 },
    {  8, 21, 14, 33 },
    { 56, 19, 34, 39 },
    {  8,  5, 46, 17 },
    { 56, 35,  2, 55 },
}
