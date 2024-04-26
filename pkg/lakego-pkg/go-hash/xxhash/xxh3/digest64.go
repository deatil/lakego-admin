package xxh3

// The size of a XXH3_64 hash value in bytes
const Size64 = 8

// The blocksize of XXH3_64 hash function in bytes
const BlockSize64 = 256

// digest64 represents the partial evaluation of a checksum.
type digest64 struct {
    s   [8]uint64
    x   [BlockSize64]byte
    nx  int
    len uint64

    seed   uint64
    secret []byte

    secretLimit       int
    nbStripesSoFar    int
    nbStripesPerBlock int
}

// newDigest64 returns a new *digest64 computing the checksum
func newDigest64(seed uint64, secret []byte) *digest64 {
    d := new(digest64)
    d.seed = seed

    d.secret = make([]byte, len(secret))
    copy(d.secret, secret)

    d.Reset()

    return d
}

func (d *digest64) Reset() {
    // buffer
    d.x = [BlockSize64]byte{}
    // bufferedSize
    d.nx = 0
    d.len = 0

    copy(d.s[:], INIT_ACC)

    d.secretLimit = len(d.secret) - STRIPE_LEN
    d.nbStripesSoFar = 0
    d.nbStripesPerBlock = d.secretLimit / SECRET_CONSUME_RATE
}

func (d *digest64) Size() int {
    return Size64
}

func (d *digest64) BlockSize() int {
    return BlockSize64
}

func (d *digest64) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)

    if len(p) == 0 {
        return
    }

    pp := p
    secret := d.secret
    acc := d.s[:]

    const stripes = INTERNALBUFFER_STRIPES

    if len(p) <= BlockSize64 - d.nx {
        copy(d.x[d.nx:], p)
        d.nx += len(p)
        return
    }

    if d.nx > 0 {
        loadSize := BlockSize64 - d.nx
        copy(d.x[d.nx:], p[:loadSize])

        p = p[loadSize:]

        consumeStripes(
            acc,
            &d.nbStripesSoFar,
            d.nbStripesPerBlock,
            d.x[:],
            stripes,
            secret,
            d.secretLimit,
        )

        d.nx = 0
    }

    if len(p) >= BlockSize64 {
        for len(p) - BlockSize64 > 0 {
            consumeStripes(
                acc,
                &d.nbStripesSoFar,
                d.nbStripesPerBlock,
                p,
                stripes,
                secret,
                d.secretLimit,
            )

            p = p[BlockSize64:]
        }

        // for last partial stripe
        offset := len(pp) - len(p)
        copy(d.x[len(d.x)-STRIPE_LEN:], pp[offset-STRIPE_LEN:])
    }

    d.nx = copy(d.x[:], p)

    return
}

func (d *digest64) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()
    return append(in, sum[:]...)
}

func (d *digest64) checkSum() (out [Size64]byte) {
    sum := d.Sum64()
    putu64be(out[:], sum)

    return
}

func (d *digest64) Sum64() uint64 {
    secret := d.secret

    if d.len > MIDSIZE_MAX {
        acc := make([]uint64, 8)
        d.hashLong(acc, secret)

        return mergeAccs(
            acc,
            secret[SECRET_MERGEACCS_START:],
            d.len * PRIME64_1,
        )
    }

    if d.seed != 0 {
        return Hash_64bits_withSeed(d.x[:d.nx], d.seed)
    }

    return Hash_64bits_withSecret(d.x[:d.nx], secret[:d.secretLimit + STRIPE_LEN])
}

func (d *digest64) hashLong(acc []uint64, secret []byte) {
    var lastStripe [STRIPE_LEN]byte
    var lastStripePtr []byte

    copy(acc, d.s[:])

    if d.nx >= STRIPE_LEN {
        /* Consume remaining stripes then point to remaining data in buffer */
        nbStripes := (d.nx - 1) / STRIPE_LEN
        nbStripesSoFar := d.nbStripesSoFar

        consumeStripes(
            acc,
            &nbStripesSoFar,
            d.nbStripesPerBlock,
            d.x[:d.nx],
            nbStripes,
            secret,
            d.secretLimit,
        )

        lastStripePtr = d.x[d.nx - STRIPE_LEN:d.nx]
    } else {
        catchupSize := STRIPE_LEN - d.nx

        copy(lastStripe[:], d.x[len(d.x) - catchupSize:])
        copy(lastStripe[catchupSize:], d.x[:d.nx])

        lastStripePtr = lastStripe[:]
    }

    /* Last stripe */
    accumulate_512(
        acc,
        lastStripePtr,
        secret[d.secretLimit - SECRET_LASTACC_START:],
    )
}
