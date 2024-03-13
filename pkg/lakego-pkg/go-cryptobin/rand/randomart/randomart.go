package randomart

/*
 * Draw an ASCII-Art representing the fingerprint so human brain can
 * profit from its built-in pattern recognition ability.
 * This technique is called "random art" and can be found in some
 * scientific publications like this original paper:
 *
 * "Hash Visualization: a New Technique to improve Real-World Security",
 * Perrig A. and Song D., 1999, International Workshop on Cryptographic
 * Techniques and E-Commerce (CrypTEC '99)
 * sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf
 *
 * The subject came up in a talk by Dan Kaminsky, too.
 *
 * If you see the picture is different, the key is different.
 * If the picture looks the same, you still know nothing.
 *
 * The algorithm used here is a worm crawling over a discrete plane,
 * leaving a trace (augmenting the field) everywhere it goes.
 * Movement is taken from dgst_raw 2bit-wise.  Bumping into walls
 * makes the respective movement vector be ignored for this turn.
 * Graphs are not unambiguous, because circles in graphs can be
 * walked in either direction.
 */

/*
 * Field sizes for the random art.  Have to be odd, so the starting point
 * can be in the exact middle of the picture, and FLDBASE should be >=8 .
 * Else pictures would be too dense, and drawing the frame would
 * fail, too, because the key type would not fit in anymore.
 */
const (
    FLDBASE   = 8
    FLDSIZE_Y = (FLDBASE + 1)
    FLDSIZE_X = (FLDBASE*2 + 1)
)

func Randomart(str string) string {
    ch := make(chan byte)

    go func() {
        defer close(ch)
        for _, v := range []byte(str) {
            ch <- v
        }
    }()

    return keyFingerprintRandomart(ch)
}

func keyFingerprintRandomart(ch chan byte) string {
    /*
     * Chars to be used after each other every time the worm
     * intersects with itself.  Matter of taste.
     */
    augment_string := " .o+=*BOX@%&#/^SE"
    var field [FLDSIZE_X][FLDSIZE_Y]byte
    len_aug := len(augment_string) - 1
    var retval [(FLDSIZE_X + 3) * (FLDSIZE_Y + 2)]byte

    /* initialize field */
    x := FLDSIZE_X / 2
    y := FLDSIZE_Y / 2

    /* process raw key */
    for input, ok := <-ch; ok; input, ok = <-ch {
        /* each byte conveys four 2-bit move commands */
        for b := 0; b < 4; b++ {
            /* evaluate 2 bit, rest is shifted later */
            if input&0x1 > 0 {
                x += 1
            } else {
                x += -1
            }

            if input&0x2 > 0 {
                y++
            } else {
                y--
            }

            /* assure we are still in bounds */
            x = MAX(x, 0)
            y = MAX(y, 0)
            x = MIN(x, FLDSIZE_X-1)
            y = MIN(y, FLDSIZE_Y-1)

            /* augment the field */
            if int(field[x][y]) < len_aug-2 {
                field[x][y]++
            }
            input = input >> 2
        }
    }

    /* mark starting point and end point*/
    field[FLDSIZE_X/2][FLDSIZE_Y/2] = byte(len_aug - 1)
    field[x][y] = byte(len_aug)

    i := 0
    retval[i] = '+'
    i++

    /* output upper border */
    for x := 0; x < FLDSIZE_X; x++ {
        retval[i] = '-'
        i++
    }
    retval[i] = '+'
    i++
    retval[i] = '\n'
    i++

    /* output content */
    for y := 0; y < FLDSIZE_Y; y++ {
        retval[i] = '|'
        i++
        for x := 0; x < FLDSIZE_X; x++ {
            retval[i] = augment_string[MIN(int(field[x][y]), len_aug)]
            i++
        }
        retval[i] = '|'
        i++
        retval[i] = '\n'
        i++
    }

    /* output lower border */
    retval[i] = '+'
    i++
    for j := 0; j < FLDSIZE_X; j++ {
        retval[i] = '-'
        i++
    }
    retval[i] = '+'
    i++

    return string(retval[0:i])
}

func MAX(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func MIN(a, b int) int {
    if a < b {
        return a
    }
    return b
}
