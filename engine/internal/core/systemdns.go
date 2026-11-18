package core

// LocalDNSAddr is the resolver TUN mode asks the host to use. It is declared
// outside the platform files because the engine's state and messages reference
// it on every OS, even where no takeover happens.
const LocalDNSAddr = "127.0.0.1"
