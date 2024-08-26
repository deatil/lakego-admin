package container

var defaultContainer = NewContainer()

func DI() *Container {
    return defaultContainer
}
