package threeway

// unsigned int = uint32

const NMBR uint32 = 11; // number of rounds is 11
const STRT_E uint32 = 0x0b0b; // round constant of first encryption round
const STRT_D uint32 = 0xb1b1; // round constant of first decryption round

func mu(a *[3]uint32) {
    // inverts the order of the bits of a
    var b [3]uint32

    b[0] = 0
    b[1] = 0
    b[2] = 0

    for i := 0; i < 32; i++ {
        b[0] <<= 1
        b[1] <<= 1
        b[2] <<= 1

        if ((*a)[0] & 1) == 1 {
            b[2] |= 1
        }

        if ((*a)[1] & 1) == 1 {
            b[1] |= 1
        }

        if ((*a)[2] & 1) == 1 {
            b[0] |= 1
        }

        (*a)[0] >>= 1
        (*a)[1] >>= 1
        (*a)[2] >>= 1
    }

    (*a)[0] = b[0]
    (*a)[1] = b[1]
    (*a)[2] = b[2]
}

func gamma(a *[3]uint32) {
    // the nonlinear step
    var b [3]uint32

    b[0] = (*a)[0] ^ ((*a)[1] | (^(*a)[2]))
    b[1] = (*a)[1] ^ ((*a)[2] | (^(*a)[0]))
    b[2] = (*a)[2] ^ ((*a)[0] | (^(*a)[1]))

    (*a)[0] = b[0]
    (*a)[1] = b[1]
    (*a)[2] = b[2]
}

func theta(a *[3]uint32) {
    // the linear step
    var b [3]uint32

    b[0] =
        (*a)[0] ^
        ((*a)[0] >> 16) ^ ((*a)[1] << 16) ^ ((*a)[1] >> 16) ^ ((*a)[2] << 16) ^
        ((*a)[1] >> 24) ^ ((*a)[2] << 8) ^ ((*a)[2] >> 8) ^ ((*a)[0] << 24) ^
        ((*a)[2] >> 16) ^ ((*a)[0] << 16) ^ ((*a)[2] >> 24) ^ ((*a)[0] << 8)

    b[1] =
        (*a)[1] ^
        ((*a)[1] >> 16) ^ ((*a)[2] << 16) ^ ((*a)[2] >> 16) ^ ((*a)[0] << 16) ^
        ((*a)[2] >> 24) ^ ((*a)[0] << 8) ^ ((*a)[0] >> 8) ^ ((*a)[1] << 24) ^
        ((*a)[0] >> 16) ^ ((*a)[1] << 16) ^ ((*a)[0] >> 24) ^ ((*a)[1] << 8)
    b[2] =
        (*a)[2] ^
        ((*a)[2] >> 16) ^ ((*a)[0] << 16) ^ ((*a)[0] >> 16) ^ ((*a)[1] << 16) ^
        ((*a)[0] >> 24) ^ ((*a)[1] << 8) ^ ((*a)[1] >> 8) ^ ((*a)[2] << 24) ^
        ((*a)[1] >> 16) ^ ((*a)[2] << 16) ^ ((*a)[1] >> 24) ^ ((*a)[2] << 8)

    (*a)[0] = b[0]
    (*a)[1] = b[1]
    (*a)[2] = b[2]
}

func pi_1(a *[3]uint32) {
    (*a)[0] = ((*a)[0] >> 10) ^ ((*a)[0] << 22)
    (*a)[2] = ((*a)[2] << 1) ^ ((*a)[2] >> 31)
}

func pi_2(a *[3]uint32) {
    (*a)[0] = ((*a)[0] << 1) ^ ((*a)[0] >> 31)
    (*a)[2] = ((*a)[2] >> 10) ^ ((*a)[2] << 22)
}

func rho(a *[3]uint32) {
    // the round function
    theta(a);
    pi_1(a);

    gamma(a);
    pi_2(a);
}

func rndcon_gen(strt uint32, rtab *[12]uint32) {
    // generates the round constants
    var i uint32

    for i = 0; i <= NMBR; i++ {
        (*rtab)[i] = strt;
        strt <<= 1;

        if (strt & 0x10000) > 0 {
            strt ^= 0x11011;
        }
    }
}
