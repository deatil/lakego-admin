// // 生成公钥私钥 / CreateKey:
// obj := ed448.
//     New().
//     GenerateKey()
//
// objPriKey := obj.
//     CreatePrivateKey().
//     // CreatePrivateKeyWithPassword("123", "AES256CBC").
//     ToKeyString()
// objPubKey := obj.
//     CreatePublicKey().
//     ToKeyString()
//
//
// // 签名验证 / Sign or Verify:
// obj := ed448.New()
//
// ctx := "123sedrftd35"
//
// pri := `-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----`
// priEn := `-----BEGIN ENCRYPTED PRIVATE KEY-----...-----END ENCRYPTED PRIVATE KEY-----`
// sig := obj.
//     FromString("test-pass").
//     FromPrivateKey([]byte(pri)).
//     // FromPrivateKeyWithPassword([]byte(priEn), "123").
//     // 其他设置, 默认为 ED448 模式, ctx 为空
//     // SetOptions("ED448", "").
//     // SetOptions("ED448", ctx).
//     // SetOptions("ED448Ph", ctx).
//     Sign().
//     ToBase64String()
//
// pub := `-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`
// text := obj.
//     FromBase64String("MjkzNzYzMDE1NjgzNDExMTM0ODE1MzgxOTAxMDIxNzQ0Nzg3NTc3NTAxNTU2MDIwNzg4OTc1MzY4Mzc0OTE5NzcyOTg3NjI1MTc2OTErNDgzNDU3NDAyMzYyODAzMDM3MzE1NjE1NDk1NDEzOTQ4MDQ3NDQ3ODA0MDE4NDY5NDA1OTA3ODExNjM1Mzk3MDEzOTY4MTM5NDg2NDc=").
//     FromPublicKey([]byte(pub)).
//     // SetOptions("ED448", "").
//     // SetOptions("ED448", ctx).
//     // SetOptions("ED448Ph", ctx).
//     Verify([]byte("test-pass")).
//     ToVerify()
package ed448
