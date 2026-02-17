package capability

var importPatterns = map[string][]Capability{
	"os":                    {CapFSRead, CapFSWrite, CapEnv},
	"io/ioutil":             {CapFSRead, CapFSWrite},
	"io/fs":                 {CapFSRead},
	"net":                   {CapNetwork},
	"net/http":              {CapNetwork},
	"net/rpc":               {CapNetwork},
	"net/smtp":              {CapNetwork},
	"os/exec":               {CapExec},
	"syscall":               {CapExec, CapFSRead, CapFSWrite},
	"golang.org/x/sys/unix": {CapExec, CapFSRead, CapFSWrite},
	"unsafe":                {CapUnsafe},
	"reflect":               {CapReflect},
	"plugin":                {CapPlugin},
	"crypto":                {CapCrypto},
	"crypto/tls":            {CapCrypto, CapNetwork},
	"crypto/rsa":            {CapCrypto},
	"crypto/aes":            {CapCrypto},
	"crypto/sha256":         {CapCrypto},
	"crypto/sha512":         {CapCrypto},
	"crypto/md5":            {CapCrypto},
	"crypto/hmac":           {CapCrypto},
	"crypto/ecdsa":          {CapCrypto},
	"crypto/ed25519":        {CapCrypto},
	"crypto/rand":           {CapCrypto},
	"crypto/x509":           {CapCrypto},
}

var callPatterns = map[string][]Capability{
	"os.Open":             {CapFSRead},
	"os.OpenFile":         {CapFSRead, CapFSWrite},
	"os.ReadFile":         {CapFSRead},
	"os.WriteFile":        {CapFSWrite},
	"os.Create":           {CapFSWrite},
	"os.Mkdir":            {CapFSWrite},
	"os.MkdirAll":         {CapFSWrite},
	"os.Remove":           {CapFSWrite},
	"os.RemoveAll":        {CapFSWrite},
	"os.Rename":           {CapFSWrite},
	"os.Getenv":           {CapEnv},
	"os.LookupEnv":        {CapEnv},
	"os.Environ":          {CapEnv},
	"os.Setenv":           {CapEnv},
	"ioutil.ReadFile":     {CapFSRead},
	"ioutil.WriteFile":    {CapFSWrite},
	"ioutil.TempFile":     {CapFSWrite},
	"ioutil.TempDir":      {CapFSWrite},
	"exec.Command":        {CapExec},
	"exec.CommandContext": {CapExec},
	"syscall.Exec":        {CapExec},
	"syscall.ForkExec":    {CapExec},
	"http.Get":            {CapNetwork},
	"http.Post":           {CapNetwork},
	"http.ListenAndServe": {CapNetwork},
	"net.Dial":            {CapNetwork},
	"net.Listen":          {CapNetwork},
	"tls.Dial":            {CapNetwork, CapCrypto},
}

func ImportCapabilities(importPath string) []Capability {
	return importPatterns[importPath]
}

func CallCapabilities(pkgName, funcName string) []Capability {
	key := pkgName + "." + funcName
	return callPatterns[key]
}
