package packet

// Protocol versions and file extensions
const (
	ProtocolVersion = "v1"
	ExtLMS          = ".lms_sig"
	ExtXMSS         = ".xmss_sig"
)

// Cryptographic Domain Separation Tags (Mandatory for cross-protocol collision prevention)
const (
	DomainStatefulDetached  = "PQPG-Stateful-Detached-Signature-" + ProtocolVersion
	DomainStatelessDetached = "PQPG-Stateless-Detached-Signature-" + ProtocolVersion
	DomainMessage           = "PQPG-Standard-Message-" + ProtocolVersion
	DomainVault             = "PQPG-Local-Vault-" + ProtocolVersion
)

const (
	SharedHeaderBoundary  = "-----BEGIN SHARED VAULT HEADER-----"
	SharedPayloadBoundary = "-----BEGIN SHARED VAULT PAYLOAD-----"
	SharedEndBoundary     = "-----END SHARED VAULT-----"
)

const (
	OuterHeaderBoundary = "-----BEGIN PQC OUTER ENVELOPE-----"
	InnerHeaderBoundary = "-----BEGIN PQC INNER METADATA-----"
	PayloadBoundary     = "-----BEGIN PQC PAYLOAD-----"
	SignatureBoundary   = "-----BEGIN PQC SIGNATURE-----"
	EndBoundary         = "-----END PQC MESSAGE-----"
	ChunkSize           = 64 * 1024
	InnerHeaderSize     = 1024
	SaltSize            = 32
	MsgIDSize           = 32
	XOFDeriveSize       = 64
)

const (
	VaultKeyExpansionVersion = "PQPG-Vault-Key-Expansion-v1"
	VaultHeaderBoundary      = "-----BEGIN PQPG VAULT METADATA-----"
	VaultPayloadBoundary     = "-----BEGIN PQPG VAULT PAYLOAD-----"
	VaultEndBoundary         = "-----END PQPG VAULT-----"
)

// ASCII Armor Headers
const (
	DetachedHeader = "-----BEGIN PQPG DETACHED SIGNATURE-----"
	DetachedFooter = "-----END PQPG DETACHED SIGNATURE-----"
)
