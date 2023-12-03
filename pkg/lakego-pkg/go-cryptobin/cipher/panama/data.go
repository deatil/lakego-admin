package panama

type panamaData struct {
    state []uint32
    gamma []uint32
    pi    []uint32
    theta []uint32
}

// #define regs(i)
func NewData(n uint32) *panamaData {
    data := &panamaData{}

    data.state = make([]uint32, n)
    data.gamma = make([]uint32, n)
    data.pi = make([]uint32, n)
    data.theta = make([]uint32, n)

    return data
}

/* move state between memory and local registers */
func (this *panamaData) READ_STATE_i(i uint32, state IState) {
    this.state[i] = state.Get(i)
}

func (this *panamaData) WRITE_STATE_i(i uint32, state IState) {
    state.With(i, this.state[i])
}

func (this *panamaData) READ_STATE(state IState) {
    this.READ_STATE_i(0, state)
    this.READ_STATE_i(1, state)
    this.READ_STATE_i(2, state)
    this.READ_STATE_i(3, state)
    this.READ_STATE_i(4, state)
    this.READ_STATE_i(5, state)
    this.READ_STATE_i(6, state)
    this.READ_STATE_i(7, state)
    this.READ_STATE_i(8, state)
    this.READ_STATE_i(9, state)
    this.READ_STATE_i(10, state)
    this.READ_STATE_i(11, state)
    this.READ_STATE_i(12, state)
    this.READ_STATE_i(13, state)
    this.READ_STATE_i(14, state)
    this.READ_STATE_i(15, state)
    this.READ_STATE_i(16, state)
}

func (this *panamaData) WRITE_STATE(state IState) {
    this.WRITE_STATE_i(0, state)
    this.WRITE_STATE_i(1, state)
    this.WRITE_STATE_i(2, state)
    this.WRITE_STATE_i(3, state)
    this.WRITE_STATE_i(4, state)
    this.WRITE_STATE_i(5, state)
    this.WRITE_STATE_i(6, state)
    this.WRITE_STATE_i(7, state)
    this.WRITE_STATE_i(8, state)
    this.WRITE_STATE_i(9, state)
    this.WRITE_STATE_i(10, state)
    this.WRITE_STATE_i(11, state)
    this.WRITE_STATE_i(12, state)
    this.WRITE_STATE_i(13, state)
    this.WRITE_STATE_i(14, state)
    this.WRITE_STATE_i(15, state)
    this.WRITE_STATE_i(16, state)
}

/* gamma, shift-invariant transformation a[i] XOR (a[i+1] OR NOT a[i+2]) */
func (this *panamaData) GAMMA_i(i, i_plus_1, i_plus_2 uint32) {
    this.gamma[i] = this.state[i] ^ (this.state[i_plus_1] | ^this.state[i_plus_2])
}

func (this *panamaData) GAMMA() {
    this.GAMMA_i( 0,  1,  2)
    this.GAMMA_i( 1,  2,  3)
    this.GAMMA_i( 2,  3,  4)
    this.GAMMA_i( 3,  4,  5)
    this.GAMMA_i( 4,  5,  6)
    this.GAMMA_i( 5,  6,  7)
    this.GAMMA_i( 6,  7,  8)
    this.GAMMA_i( 7,  8,  9)
    this.GAMMA_i( 8,  9, 10)
    this.GAMMA_i( 9, 10, 11)
    this.GAMMA_i(10, 11, 12)
    this.GAMMA_i(11, 12, 13)
    this.GAMMA_i(12, 13, 14)
    this.GAMMA_i(13, 14, 15)
    this.GAMMA_i(14, 15, 16)
    this.GAMMA_i(15, 16,  0)
    this.GAMMA_i(16,  0,  1)
}

/* pi, permute and cyclicly rotate the state words */
func (this *panamaData) PI_i(i, j, k uint32) {
    this.pi[i] = tau(this.gamma[j], k)
}

func (this *panamaData) PI() {
    this.pi[0] = this.gamma[0]
    this.PI_i( 1,  7,  1)
    this.PI_i( 2, 14,  3)
    this.PI_i( 3,  4,  6)
    this.PI_i( 4, 11, 10)
    this.PI_i( 5,  1, 15)
    this.PI_i( 6,  8, 21)
    this.PI_i( 7, 15, 28)
    this.PI_i( 8,  5,  4)
    this.PI_i( 9, 12, 13)
    this.PI_i(10,  2, 23)
    this.PI_i(11,  9,  2)
    this.PI_i(12, 16, 14)
    this.PI_i(13,  6, 27)
    this.PI_i(14, 13,  9)
    this.PI_i(15,  3, 24)
    this.PI_i(16, 10,  8)
}

/* theta, shift-invariant transformation a[i] XOR a[i+1] XOR a[i+4] */
func (this *panamaData) THETA_i(i, i_plus_1, i_plus_4 uint32) {
    this.theta[i] = this.pi[i] ^ this.pi[i_plus_1] ^ this.pi[i_plus_4]
}

func (this *panamaData) THETA() {
    this.THETA_i( 0,  1,  4)
    this.THETA_i( 1,  2,  5)
    this.THETA_i( 2,  3,  6)
    this.THETA_i( 3,  4,  7)
    this.THETA_i( 4,  5,  8)
    this.THETA_i( 5,  6,  9)
    this.THETA_i( 6,  7, 10)
    this.THETA_i( 7,  8, 11)
    this.THETA_i( 8,  9, 12)
    this.THETA_i( 9, 10, 13)
    this.THETA_i(10, 11, 14)
    this.THETA_i(11, 12, 15)
    this.THETA_i(12, 13, 16)
    this.THETA_i(13, 14,  0)
    this.THETA_i(14, 15,  1)
    this.THETA_i(15, 16,  2)
    this.THETA_i(16,  0,  3)
}

/* sigma, merge two buffer stages with current state */
func (this *panamaData) SIGMA_L_i(i uint32, L IState) {
    this.state[i] = this.theta[i] ^ L.Get(i-1)
}

func (this *panamaData) SIGMA_B_i(i uint32, b IState) {
    this.state[i] = this.theta[i] ^ b.Get(i-9)
}

func (this *panamaData) SIGMA(L IState, b IState) {
    this.state[0] = this.theta[0] ^ 0x00000001

    this.SIGMA_L_i(1, L)
    this.SIGMA_L_i(2, L)
    this.SIGMA_L_i(3, L)
    this.SIGMA_L_i(4, L)
    this.SIGMA_L_i(5, L)
    this.SIGMA_L_i(6, L)
    this.SIGMA_L_i(7, L)
    this.SIGMA_L_i(8, L)

    this.SIGMA_B_i(9, b)
    this.SIGMA_B_i(10, b)
    this.SIGMA_B_i(11, b)
    this.SIGMA_B_i(12, b)
    this.SIGMA_B_i(13, b)
    this.SIGMA_B_i(14, b)
    this.SIGMA_B_i(15, b)
    this.SIGMA_B_i(16, b)
}

/* lambda, update the 256-bit wide by 32-stage LFSR buffer */
func (this *panamaData) LAMBDA_25_i(i uint32, ptap_25 IState, ptap_0 IState) {
    tmp := ptap_25.Get(i) ^ ptap_0.Get((i+2) & (PAN_STAGE_SIZE-1))

    ptap_25.With(i, tmp)
}

func (this *panamaData) LAMBDA_0_i(i, source uint32, ptap_0 IState) {
    tmp := source ^ ptap_0.Get(i)

    ptap_0.With(i, tmp)
}

func (this *panamaData) LAMBDA_25_UPDATE(i uint32, ptap_25 IState, ptap_0 IState) {
    this.LAMBDA_25_i(0, ptap_25, ptap_0)
    this.LAMBDA_25_i(1, ptap_25, ptap_0)
    this.LAMBDA_25_i(2, ptap_25, ptap_0)
    this.LAMBDA_25_i(3, ptap_25, ptap_0)
    this.LAMBDA_25_i(4, ptap_25, ptap_0)
    this.LAMBDA_25_i(5, ptap_25, ptap_0)
    this.LAMBDA_25_i(6, ptap_25, ptap_0)
    this.LAMBDA_25_i(7, ptap_25, ptap_0)
}

func (this *panamaData) LAMBDA_0_PULL(ptap_0 IState) {
    this.LAMBDA_0_i(0, this.state[1], ptap_0)
    this.LAMBDA_0_i(1, this.state[2], ptap_0)
    this.LAMBDA_0_i(2, this.state[3], ptap_0)
    this.LAMBDA_0_i(3, this.state[4], ptap_0)
    this.LAMBDA_0_i(4, this.state[5], ptap_0)
    this.LAMBDA_0_i(5, this.state[6], ptap_0)
    this.LAMBDA_0_i(6, this.state[7], ptap_0)
    this.LAMBDA_0_i(7, this.state[8], ptap_0)
}

func (this *panamaData) LAMBDA_0_PUSH(ptap_0 IState, L IState) {
    this.LAMBDA_0_i(0, L.Get(0), ptap_0)
    this.LAMBDA_0_i(1, L.Get(1), ptap_0)
    this.LAMBDA_0_i(2, L.Get(2), ptap_0)
    this.LAMBDA_0_i(3, L.Get(3), ptap_0)
    this.LAMBDA_0_i(4, L.Get(4), ptap_0)
    this.LAMBDA_0_i(5, L.Get(5), ptap_0)
    this.LAMBDA_0_i(6, L.Get(6), ptap_0)
    this.LAMBDA_0_i(7, L.Get(7), ptap_0)
}

/* avoid temporary register for tap 31 by finishing updating tap 25 before updating tap 0 */
func (this *panamaData) LAMBDA_PULL(i uint32, ptap_25 IState, ptap_0 IState) {
    this.LAMBDA_25_UPDATE(i, ptap_25, ptap_0)
    this.LAMBDA_0_PULL(ptap_0)
}

func (this *panamaData) LAMBDA_PUSH(i uint32, ptap_25 IState, ptap_0 IState, L IState) {
    this.LAMBDA_25_UPDATE(i, ptap_25, ptap_0)
    this.LAMBDA_0_PUSH(ptap_0, L)
}
