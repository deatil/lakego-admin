package panama

type IState interface {
    With(i uint32, word uint32)
    Get(i uint32) (word uint32)
}

type PAN_STAGE struct {
    word [PAN_STAGE_SIZE]uint32
}

func (this *PAN_STAGE) With(i uint32, word uint32) {
    this.word[i] = word
}

func (this *PAN_STAGE) Get(i uint32) (word uint32) {
    return this.word[i]
}

type PAN_BUFFER struct {
    stage [PAN_STAGES]PAN_STAGE
    tap_0 int32
}

type PAN_STATE struct {
    word [PAN_STATE_SIZE]uint32
}

func (this *PAN_STATE) With(i uint32, word uint32) {
    this.word[i] = word
}

func (this *PAN_STATE) Get(i uint32) (word uint32) {
    return this.word[i]
}

