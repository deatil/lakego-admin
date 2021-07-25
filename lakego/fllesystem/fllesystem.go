package fllesystem

import(
    "lakego-admin/lakego/fllesystem/config"
    "lakego-admin/lakego/fllesystem/intrface/adapter"
)

type Fllesystem struct {
    adapter adapter.Adapter
    config config.Config
}

func (fs *Fllesystem) setConfig() {

}

func (fs *Fllesystem) getConfig() {

}

func (fs *Fllesystem) prepareConfig(settings map[string]interface{}) {
    conf := config.New(settings)
    conf.SetFallback(fs.getConfig())
}

func (fs *Fllesystem) getAdapter() {

}

func (fs *Fllesystem) has() {

}

func (fs *Fllesystem) write() {

}

func (fs *Fllesystem) writeStream() {

}

func (fs *Fllesystem) put() {

}

func (fs *Fllesystem) putStream() {

}

func (fs *Fllesystem) readAndDelete() {

}

func (fs *Fllesystem) update() {

}

func (fs *Fllesystem) updateStream() {

}

func (fs *Fllesystem) read() {

}

func (fs *Fllesystem) readStream() {

}

func (fs *Fllesystem) rename() {

}

func (fs *Fllesystem) copy() {

}

func (fs *Fllesystem) delete() {

}

func (fs *Fllesystem) deleteDir() {

}

func (fs *Fllesystem) createDir() {

}

func (fs *Fllesystem) listContents() {

}

func (fs *Fllesystem) getMimetype() {

}

func (fs *Fllesystem) getTimestamp() {

}

func (fs *Fllesystem) getVisibility() {

}

func (fs *Fllesystem) getSize() {

}

func (fs *Fllesystem) setVisibility() {

}

func (fs *Fllesystem) getMetadata() {

}

func (fs *Fllesystem) get() {

}
