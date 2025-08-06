package msasigner

import (
	"bytes"
	"testing"

	"github.com/omnes-tech/msamisc/formatting"
)

func TestEthereumSignedMessageMount(t *testing.T) {
	t.Run("Should mount Ethereum Signed Message correctly", func(t *testing.T) {
		msg := []byte("There is no spoon")
		expected := []byte("\x19Ethereum Signed Message:\n17There is no spoon")

		result := formatting.WrapMessage(msg)

		if !bytes.Equal(result, expected) {
			t.Fatalf(`Expected mounted Ethereum Signed Message to be %q, but got %q`, expected, result)
		}
	})
}
