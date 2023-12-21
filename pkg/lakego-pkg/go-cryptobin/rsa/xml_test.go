package rsa

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var testPrivateKeyCheck = `<RSAKeyValue>
    <Modulus>tnSuqI5CVLcSyuYtD8xe4YJSekOTNuvQVCxN6ICny0aq2f3NjS4jqggKS0HBAW6sdS+eRFgmANzSWDuN8+mOZPx0iksNiOY1nYgeO6qsgmnGe6gfspgad42rW/90z+6FA0ll1eYT2rZJAypAKB+BPoFl0EmxhDBmdvK4VihR9FmWpX9+KqJv5ZwLu2D/1LRlYDPKTLPT3HPOqwZPzVtuyeJIJa/ldZhDBO3bDQgvyW2Yn/fItgTT4E0baJPswc6vXVr0PKgPeDDaCMyfrdKDm27omJZ4brzhnKurnvEkfMzBFGrmp6ch06HtQXQJpl+z6d0mHzwfeSachULTc3JogQ==</Modulus>
    <Exponent>AQAB</Exponent>
    <D>p0+OTjDNsKOEjxzNm5wcMYzxFv7ag1Vw348VDizUMXqm92le0aTKvYPL9MDiPO8BJCC7cA6pIsdb9978x/uXQRGjyKEUU0JPThrhJnPW52wZv5EnJ/2E37bAuYci1f3yaVYoFSJ7eGcJwuY+mMxzFx9PftXk+8PqYg8nbJJivL7Pko1IoX6k2dIG/iMjuffnjyYOIqcpNfpnDDwvrkiJ9G6A7ZF6LLweA7bdaSaSpjGynW8rot7LIULTJhugNtPRbdCih3nZ99+ifBpsyCX7bHVSrb3he6FAME7+fW24CyX3bBkqPJWs4/CsldgqwTeJKu0LSaR+aE3GmKsE/kDvwQ==</D>
    <P>8hUrSJ/jBK2QAHamhNz+zqY+qIDQZt182RR3lOvNQ6bH0d2WnH3DCxBpKdu5KApQZCPXF/VfFGniKMb9tCsfmOpvo84srAu//ateqqNeQlPhu0XY3zzOaPqHpCOKZsh2ym+1pzyskgNQSMA7+0AkRQI056jDSUTnvnCpuizbQ6k=</P>
    <Q>wPH1nrVYJ/E3SBWrirhGNdd71WTuuBHZlXJI1f0COaZ7RttxXZfSCZ9LHc70aJbhBPdqSDekf/HbnOqLhfuNFtwB+HIB6QupDM7sWGkZUsOWvVrH2/kzbv7PvNCXfxhB5b+zIRKA5WuAE4Mt9UCR+SiKkLDObrsKkPwtqPYShRk=</Q>
    <DP>nULfQWiMg6d0mrh5aGpgJUKeBbzYpVpRFnxTSqz8RWx89nqqsrKIGBHrH0QbvkUlAEjAHFJMF+jJAJB0k6xH9ICnUZRINOPVLyc6ckN6oj/3rj6rqinINS47G4fzCt5DPTLgoOmreZcpenlW/dsnNKVAVRWu91QJ8A8kU0t8jTE=</DP>
    <DQ>QsG0nOPbi35PBTbSMl3NlQVoSA3y9mbepHF1N+yhH3c1ge+dCqfjuQaPQ9H+CE3jrwc3k6ME3Gu+80zHV2UQjM80M1Smyo4JQHA7n99FLriTaBKHwdk37XhmQcreD9BBxI8OGCxBwp7uIlIpzYg4uT9IqgUyd2dpoX5PAf2ZrMk=</DQ>
    <InverseQ>kbS26iD2DmosCrajMCfZoKqOgX5pnZzI4ZIGv0uqe1bgzRc8FvHszMg/SlRtVnPCQEHmHEf6m9xAT3nyGvDXSCA2RXTJ7jA1Ddf3Z5JTcwCBMNsHLFZtZfnuWRdgzlSjYiNWVYtbBd0Rk3QACqGIfVnn2IBBxmXkWwOKEPOVLRI=</InverseQ>
</RSAKeyValue>`;
var testPublicKeyCheck = `<RSAKeyValue>
    <Modulus>tnSuqI5CVLcSyuYtD8xe4YJSekOTNuvQVCxN6ICny0aq2f3NjS4jqggKS0HBAW6sdS+eRFgmANzSWDuN8+mOZPx0iksNiOY1nYgeO6qsgmnGe6gfspgad42rW/90z+6FA0ll1eYT2rZJAypAKB+BPoFl0EmxhDBmdvK4VihR9FmWpX9+KqJv5ZwLu2D/1LRlYDPKTLPT3HPOqwZPzVtuyeJIJa/ldZhDBO3bDQgvyW2Yn/fItgTT4E0baJPswc6vXVr0PKgPeDDaCMyfrdKDm27omJZ4brzhnKurnvEkfMzBFGrmp6ch06HtQXQJpl+z6d0mHzwfeSachULTc3JogQ==</Modulus>
    <Exponent>AQAB</Exponent>
</RSAKeyValue>`;

func Test_ParseAndMarshalPublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    testPub := []byte(testPublicKeyCheck)
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

    testPri := []byte(testPrivateKeyCheck)
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
