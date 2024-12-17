package panama

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const NULL = 0

const WORDLENGTH = 32
const ONES       = 0xffffffff

const PAN_STAGE_SIZE = 8
const PAN_STAGES     = 32
const PAN_STATE_SIZE = 17

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/panama: invalid key size " + strconv.Itoa(int(k))
}

type panamaCipher struct {
    buffer PAN_BUFFER
    stated PAN_STATE
    wkeymat [8]uint32
    keymat [32]byte
    keymat_pointer int32
}

// NewCipher creates and returns a new cipher.Stream.
// key bytes and src bytes is use BigEndian
func NewCipher(key []byte) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 32:
            break
        default:
            return nil, KeySizeError(len(key))
    }

    c := new(panamaCipher)
    c.expandKey(key)

    return c, nil
}

func (this *panamaCipher) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }
    if len(dst) < len(src) {
        panic("go-cryptobin/panama: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/panama: invalid buffer overlap")
    }

    var i int32

    /* initialize the Panama state machine for a fresh crypting operation */
    for i = 0; i < int32(len(src)); i++ {
        if this.keymat_pointer == 32 {
            wkeymat := this.pan_pull(nil, this.wkeymat[:], 1, &this.buffer, &this.stated)
            copy(this.wkeymat[0:], wkeymat)

            this.keymat_pointer = 0

            this.keymat = keymatToBytes(this.wkeymat)
        }

        dst[i] = src[i] ^ this.keymat[this.keymat_pointer]

        this.keymat_pointer++
    }
}

func (this *panamaCipher) expandKey(key []byte) {
    this.buffer = PAN_BUFFER{}
    this.stated = PAN_STATE{}

    var in_key []uint32

    keyints := bytesToUint32s(key[:16])
    in_key = append(in_key, keyints[:]...)

    keyints = bytesToUint32s(key[16:])
    in_key = append(in_key, keyints[:]...)

    this.initialize(in_key, WORDLENGTH, nil, 0)
}

func (this *panamaCipher) initialize(
    in_key []uint32,
    keysize int32,
    init_vec []uint32,
    vecsize int32,
) {
    var keyblocks int32 = (8 * keysize) / (PAN_STAGE_SIZE * WORDLENGTH);
    var vecblocks int32 = (8 * vecsize) / (PAN_STAGE_SIZE * WORDLENGTH);

    /* initialize the Panama state machine for a fresh crypting operation */
    this.pan_reset(&this.buffer, &this.stated)
    this.pan_push(in_key, uint32(keyblocks), &this.buffer, &this.stated)

    if len(init_vec) != 0 {
        this.pan_push(init_vec, uint32(vecblocks), &this.buffer, &this.stated)
    }

    this.pan_pull(nil, nil, 32, &this.buffer, &this.stated);

    wkeymat := this.pan_pull(nil, this.wkeymat[:], 1, &this.buffer, &this.stated)
    copy(this.wkeymat[0:], wkeymat)

    this.keymat_pointer = 0

    this.keymat = keymatToBytes(this.wkeymat)
}

/**************************************************************************+
*
*  pan_pull() - Performs multiple iterations of the Panama 'Pull' operation.
*               The input and output arrays are treated as integer multiples
*               of Panama's natural 256-bit block size.
*
*               Input and output arrays may be disjoint or coincident but
*               may not be overlapped if offset from one another.
*
*               If 'In' is a NULL pointer then output is taken direct from
*               the state machine (used for hash output). If 'Out' is a NULL
*               pointer then a dummy 'Pull' is performed. Otherwise 'In' is
*               XOR combined with the state machine to produce 'Out'
*               (used for stream encryption / decryption).
*
+**************************************************************************/
func (this *panamaCipher) pan_pull(
    In []uint32,
    Out []uint32,
    pan_blocks uint32,
    buffer *PAN_BUFFER,
    state *PAN_STATE,
) []uint32 {
    /* 17-word finite-state machine  */
    var i uint32

    data := NewData(17)

    var tap_0 uint32

    var ptap_0, ptap_25 *PAN_STAGE
    var L, b *PAN_STAGE

    var null_in = [PAN_STAGE_SIZE]uint32{ 0, 0, 0, 0, 0, 0, 0, 0 }

    var dummy_out [PAN_STAGE_SIZE]uint32
    var in_step, out_step uint32

    in_step = PAN_STAGE_SIZE
    out_step = PAN_STAGE_SIZE

    if (len(In) == 0 || len(Out) == 0) {
        In = null_in[:]
        in_step = 0
    }

    if (len(Out) == 0) {
        Out = dummy_out[:]
        out_step = 0
    }

    /* copy buffer pointers and state to registers */
    tap_0 = uint32(buffer.tap_0)
    data.READ_STATE(state)

    newOut := make([]uint32, len(Out))

    /* rho, cascade of state update operations */

    for i = 0; i < pan_blocks; i++ {
        /* apply state output to crypto buffer */
        Out[0] = In[0] ^ data.state[9]
        Out[1] = In[1] ^ data.state[10]
        Out[2] = In[2] ^ data.state[11]
        Out[3] = In[3] ^ data.state[12]
        Out[4] = In[4] ^ data.state[13]
        Out[5] = In[5] ^ data.state[14]
        Out[6] = In[6] ^ data.state[15]
        Out[7] = In[7] ^ data.state[16]

        copy(newOut[i*out_step:], Out[:8])

        Out = Out[i*out_step:]
        In = In[i*in_step:]

        data.GAMMA()        /* perform non-linearity stage */

        data.PI()           /* perform bit-dispersion stage */

        data.THETA()        /* perform diffusion stage */

        /* calculate pointers to taps 4 and 16 for sigma based on current position of tap 0 */
        L = &buffer.stage[(tap_0 + 4) & (PAN_STAGES - 1)]
        b = &buffer.stage[(tap_0 + 16) & (PAN_STAGES - 1)]

        /* move tap_0 left by one stage, equivalent to shifting LFSR one stage right */
        tap_0 = (tap_0 - 1) & (PAN_STAGES - 1)

        /* set tap pointers for use by lambda */
        ptap_0 = &buffer.stage[tap_0]
        ptap_25 = &buffer.stage[(tap_0 + 25) & (PAN_STAGES - 1)]

        data.LAMBDA_PULL(i, ptap_25, ptap_0);	/* update the LFSR buffer */

        /* postpone sigma until after lambda in order to avoid extra temporaries for feedback path */
        /* note that sigma gets to use the old positions of taps 4 and 16 */

        data.SIGMA(L, b)        /* perform buffer injection stage */
    }

    /* write buffer pointer and state back to memory */
    buffer.tap_0 = int32(tap_0)
    data.WRITE_STATE(state)

    return newOut
}

/**************************************************************************+
*
*  pan_push() - Performs multiple iterations of the Panama 'Push' operation.
*               The input array is treated as an integer multiple of the
*               256-bit blocks which are Panama's natural input size.
*
+**************************************************************************/
func (this *panamaCipher) pan_push(
    In []uint32,
    pan_blocks uint32,
    buffer *PAN_BUFFER,
    state *PAN_STATE,
) {
    /* 17-word finite-state machine  */
    var i uint32

    data := NewData(17)

    var tap_0 uint32
    var ptap_0, ptap_25 *PAN_STAGE
    var L []PAN_STAGE = make([]PAN_STAGE, 0)
    var b *PAN_STAGE

    /* copy buffer pointers and state to registers */
    tap_0 = uint32(buffer.tap_0)
    data.READ_STATE(state)

    /* we assume pointer to input buffer is compatible with pointer to PAN_STAGE */
    var pan_states [8]uint32

    for i = 0; i < uint32(len(In)); i += PAN_STAGE_SIZE {
        copy(pan_states[0:], In[i:])

        L = append(L, PAN_STAGE{pan_states})
    }

    /* rho, cascade of state update operations */

    for i = 0; i < pan_blocks; i++ {
        data.GAMMA()     /* perform non-linearity stage */

        data.PI()        /* perform bit-dispersion stage */

        data.THETA()     /* perform diffusion stage */

        /* calculate pointer to tap 16 for sigma based on current position of tap 0 */
        b = &buffer.stage[(tap_0 + 16) & (PAN_STAGES - 1)]

        /* move tap_0 left by one stage, equivalent to shifting LFSR one stage right */
        tap_0 = (tap_0 - 1) & (PAN_STAGES - 1)

        /* set tap pointers for use by lambda */
        ptap_0 = &buffer.stage[tap_0]
        ptap_25 = &buffer.stage[(tap_0 + 25) & (PAN_STAGES - 1)]

        data.LAMBDA_PUSH(i, ptap_25, ptap_0, &L[i])	/* update the LFSR buffer */

        /* postpone sigma until after lambda in order to avoid extra temporaries for feedback path */
        /* note that sigma gets to use the old positions of taps 4 and 16 */

        data.SIGMA(&L[i], b)     /* perform buffer injection stage */

        /* In += PAN_STAGE_SIZE; */
    }

    /* write buffer pointer and state back to memory */
    buffer.tap_0 = int32(tap_0)
    data.WRITE_STATE(state)
}

/**************************************************************************+
*
*  pan_reset() - Initializes an LFSR buffer and Panama state machine to
*                all zeros, ready for a new hash to be accumulated or to
*                re-synchronize or start up an encryption key-stream.
*
+**************************************************************************/
func (this *panamaCipher) pan_reset(buffer *PAN_BUFFER, state *PAN_STATE) {
    var i, j int32

    buffer.tap_0 = 0

    for j = 0; j < PAN_STAGES; j++ {
        for i = 0; i < PAN_STAGE_SIZE; i++ {
            buffer.stage[j].word[i] = 0
        }
    }

    for i = 0; i < PAN_STATE_SIZE; i++ {
        state.word[i] = 0
    }
}

