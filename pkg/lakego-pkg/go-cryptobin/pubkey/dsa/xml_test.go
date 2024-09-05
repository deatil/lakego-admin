package dsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testPrivateKey = "<DSAKeyValue><P>v9B+VOY0xg7z8tlT+7ALGLZDGCcKbheTYd7eIUfBmU8BloVn97DnU49HGWx/KIx5BRkf87JAtUBENQ+NEVoNRIvsowOuGY5biP5xdCOw+OuKEoVobgXM6cQ+FHhm7dKCOfKw4onlBZSbykyE/g3z9EJjlmSmMgB/yCGHSJSyOTU=</P><Q>rpQWFUx8Y3w2CDXc3MVuP8ugjXk=</Q><G>JQZg0wH3U0zy1DvlVrL7BwveZncLNcVaxG8HvRKMHiON+w2BAzGM7xBnXe96nJ/BStvJFzJq6y29azD/kvC2U9/t2ALh8PanBhWlbmTIS6BopyJ0RxpuM5sRtTamXnLgI7y4B6rTfnFfFX7U8eldV6CRUmDifh0ZZxbD78/BFYo=</G><Y>R3busGxRGdW6lTbcGZAQlvkoLlxhIkQqPeLepBx4mHXcd6epC4IK/FuMOM0stLuwX5WFz15oxILoxZDfyO0WwiP0bjyJ9t7DrerYdH7JXhg1aeRzhKJFaQPojYkvla3cNDaoZPw25jQ8kEigvL69HDxFm1nPM076b9dBEV+yymc=</Y><J>AAAAARlGTpkJFSjk5pWsdf0YhNUiTmDoBG4wVsb1dU0vn/67Z+du7y8R4HfRwoAUvKBzNuclISy1Zx6y9XuyauAtgL315gpQwlbXkZfeTNVlNOajUDd0Y3g+MYuNZ2iYqbxIv4DDfvhcHm6sSX5Z1A==</J><Seed>fpbN84HbBsVGshjSsj3Rl6iHPcY=</Seed><PgenCounter>Alo=</PgenCounter><X>q5FlYAqyvS2hR8UM3FUtrhF6ZqE=</X></DSAKeyValue>";
var testPublicKey = "<DSAKeyValue><P>v9B+VOY0xg7z8tlT+7ALGLZDGCcKbheTYd7eIUfBmU8BloVn97DnU49HGWx/KIx5BRkf87JAtUBENQ+NEVoNRIvsowOuGY5biP5xdCOw+OuKEoVobgXM6cQ+FHhm7dKCOfKw4onlBZSbykyE/g3z9EJjlmSmMgB/yCGHSJSyOTU=</P><Q>rpQWFUx8Y3w2CDXc3MVuP8ugjXk=</Q><G>JQZg0wH3U0zy1DvlVrL7BwveZncLNcVaxG8HvRKMHiON+w2BAzGM7xBnXe96nJ/BStvJFzJq6y29azD/kvC2U9/t2ALh8PanBhWlbmTIS6BopyJ0RxpuM5sRtTamXnLgI7y4B6rTfnFfFX7U8eldV6CRUmDifh0ZZxbD78/BFYo=</G><Y>R3busGxRGdW6lTbcGZAQlvkoLlxhIkQqPeLepBx4mHXcd6epC4IK/FuMOM0stLuwX5WFz15oxILoxZDfyO0WwiP0bjyJ9t7DrerYdH7JXhg1aeRzhKJFaQPojYkvla3cNDaoZPw25jQ8kEigvL69HDxFm1nPM076b9dBEV+yymc=</Y><J>AAAAARlGTpkJFSjk5pWsdf0YhNUiTmDoBG4wVsb1dU0vn/67Z+du7y8R4HfRwoAUvKBzNuclISy1Zx6y9XuyauAtgL315gpQwlbXkZfeTNVlNOajUDd0Y3g+MYuNZ2iYqbxIv4DDfvhcHm6sSX5Z1A==</J><Seed>fpbN84HbBsVGshjSsj3Rl6iHPcY=</Seed><PgenCounter>Alo=</PgenCounter></DSAKeyValue>";

var testPrivateKeyCheck = `<DSAKeyValue>
    <P>v9B+VOY0xg7z8tlT+7ALGLZDGCcKbheTYd7eIUfBmU8BloVn97DnU49HGWx/KIx5BRkf87JAtUBENQ+NEVoNRIvsowOuGY5biP5xdCOw+OuKEoVobgXM6cQ+FHhm7dKCOfKw4onlBZSbykyE/g3z9EJjlmSmMgB/yCGHSJSyOTU=</P>
    <Q>rpQWFUx8Y3w2CDXc3MVuP8ugjXk=</Q>
    <G>JQZg0wH3U0zy1DvlVrL7BwveZncLNcVaxG8HvRKMHiON+w2BAzGM7xBnXe96nJ/BStvJFzJq6y29azD/kvC2U9/t2ALh8PanBhWlbmTIS6BopyJ0RxpuM5sRtTamXnLgI7y4B6rTfnFfFX7U8eldV6CRUmDifh0ZZxbD78/BFYo=</G>
    <Y>R3busGxRGdW6lTbcGZAQlvkoLlxhIkQqPeLepBx4mHXcd6epC4IK/FuMOM0stLuwX5WFz15oxILoxZDfyO0WwiP0bjyJ9t7DrerYdH7JXhg1aeRzhKJFaQPojYkvla3cNDaoZPw25jQ8kEigvL69HDxFm1nPM076b9dBEV+yymc=</Y>
    <X>q5FlYAqyvS2hR8UM3FUtrhF6ZqE=</X>
</DSAKeyValue>`;
var testPublicKeyCheck = `<DSAKeyValue>
    <P>v9B+VOY0xg7z8tlT+7ALGLZDGCcKbheTYd7eIUfBmU8BloVn97DnU49HGWx/KIx5BRkf87JAtUBENQ+NEVoNRIvsowOuGY5biP5xdCOw+OuKEoVobgXM6cQ+FHhm7dKCOfKw4onlBZSbykyE/g3z9EJjlmSmMgB/yCGHSJSyOTU=</P>
    <Q>rpQWFUx8Y3w2CDXc3MVuP8ugjXk=</Q>
    <G>JQZg0wH3U0zy1DvlVrL7BwveZncLNcVaxG8HvRKMHiON+w2BAzGM7xBnXe96nJ/BStvJFzJq6y29azD/kvC2U9/t2ALh8PanBhWlbmTIS6BopyJ0RxpuM5sRtTamXnLgI7y4B6rTfnFfFX7U8eldV6CRUmDifh0ZZxbD78/BFYo=</G>
    <Y>R3busGxRGdW6lTbcGZAQlvkoLlxhIkQqPeLepBx4mHXcd6epC4IK/FuMOM0stLuwX5WFz15oxILoxZDfyO0WwiP0bjyJ9t7DrerYdH7JXhg1aeRzhKJFaQPojYkvla3cNDaoZPw25jQ8kEigvL69HDxFm1nPM076b9dBEV+yymc=</Y>
</DSAKeyValue>`;

func Test_ParseAndMarshalPublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPub := []byte(testPublicKey)
    pub, err1 := ParseXMLPublicKey(testPub)

    assertError(err1, "ParseAndMarshalPublicKey-Error")

    xmlPub, err2 := MarshalXMLPublicKey(pub)
    assertError(err2, "ParseAndMarshalPublicKey-Error2")

    assertEqual(testPublicKeyCheck, string(xmlPub), "ParseAndMarshalPublicKey")
}

func Test_ParseAndMarshalPublicKey2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPub := []byte(testPublicKeyCheck)
    pub, err1 := ParseXMLPublicKey(testPub)

    assertError(err1, "ParseAndMarshalPublicKey2-Error")

    xmlPub, err2 := MarshalXMLPublicKey(pub)
    assertError(err2, "ParseAndMarshalPublicKey2-Error2")

    assertEqual(testPublicKeyCheck, string(xmlPub), "ParseAndMarshalPublicKey2")
}

func Test_ParseAndMarshalPrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPri := []byte(testPrivateKey)
    pri, err1 := ParseXMLPrivateKey(testPri)

    assertError(err1, "ParseAndMarshalPrivateKey-Error")

    xmlPri, err2 := MarshalXMLPrivateKey(pri)
    assertError(err2, "ParseAndMarshalPrivateKey-Error2")

    assertEqual(testPrivateKeyCheck, string(xmlPri), "ParseAndMarshalPrivateKey")
}

func Test_ParseAndMarshalPrivateKey2(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPri := []byte(testPrivateKeyCheck)
    pri, err1 := ParseXMLPrivateKey(testPri)

    assertError(err1, "ParseAndMarshalPrivateKey2-Error")

    xmlPri, err2 := MarshalXMLPrivateKey(pri)
    assertError(err2, "ParseAndMarshalPrivateKey2-Error2")

    assertEqual(testPrivateKeyCheck, string(xmlPri), "ParseAndMarshalPrivateKey2")
}
