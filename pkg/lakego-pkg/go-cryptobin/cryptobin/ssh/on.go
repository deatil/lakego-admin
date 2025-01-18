package ssh

// On Error
func (this SSH) OnError(fn func([]error)) SSH {
    fn(this.Errors)

    return this
}

