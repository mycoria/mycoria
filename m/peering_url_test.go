package m

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func parseT(t *testing.T, definition string) *PeeringURL {
	t.Helper()

	tr, err := ParsePeeringURL(definition)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	return tr
}

func parseTError(definition string) error {
	_, err := ParsePeeringURL(definition)
	return err
}

func TestPeeringURLParsing(t *testing.T) {
	t.Parallel()

	// test parsing

	assert.Equal(t, &PeeringURL{
		Protocol: "tcp",
		Port:     47369,
	}, parseT(t, "tcp:47369"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "smtp",
		Port:     25,
	}, parseT(t, "smtp:25"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "smtp",
		Port:     25,
	}, parseT(t, "smtp://:25"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "smtp",
		Port:     587,
	}, parseT(t, "smtp:587"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "imap",
		Port:     143,
	}, parseT(t, "imap:143"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Port:     80,
	}, parseT(t, "http:80"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Domain:   "example.com",
		Port:     80,
	}, parseT(t, "http://example.com:80"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "https",
		Port:     443,
	}, parseT(t, "https:443"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "ws",
		Port:     80,
	}, parseT(t, "ws:80"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "wss",
		Domain:   "example.com",
		Port:     443,
		Path:     "/mycoria",
	}, parseT(t, "wss://example.com:443/mycoria"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Domain:   "example.com",
		Port:     80,
	}, parseT(t, "http://example.com:80"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Domain:   "example.com",
		Port:     80,
		Path:     "/test%20test",
	}, parseT(t, "http://example.com:80/test test"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Domain:   "example.com",
		Port:     80,
		Path:     "/test%20test",
	}, parseT(t, "http://example.com:80/test%20test"), "should match")

	assert.Equal(t, &PeeringURL{
		Protocol: "http",
		Domain:   "example.com",
		Port:     80,
		Path:     "/test?key=value",
	}, parseT(t, "http://example.com:80/test?key=value"), "should match")

	// test parsing and formatting

	assert.Equal(t, "mycoria:47369",
		parseT(t, "mycoria:47369").String(), "should match")
	assert.Equal(t, "smtp:25",
		parseT(t, "smtp:25").String(), "should match")
	assert.Equal(t, "smtp:25",
		parseT(t, "smtp://:25").String(), "should match")
	assert.Equal(t, "smtp:587",
		parseT(t, "smtp:587").String(), "should match")
	assert.Equal(t, "imap:143",
		parseT(t, "imap:143").String(), "should match")
	assert.Equal(t, "http:80",
		parseT(t, "http:80").String(), "should match")
	assert.Equal(t, "http://example.com:80",
		parseT(t, "http://example.com:80").String(), "should match")
	assert.Equal(t, "https:443",
		parseT(t, "https:443").String(), "should match")
	assert.Equal(t, "ws:80",
		parseT(t, "ws:80").String(), "should match")
	assert.Equal(t, "wss://example.com:443/mycoria",
		parseT(t, "wss://example.com:443/mycoria").String(), "should match")
	assert.Equal(t, "http://example.com:80",
		parseT(t, "http://example.com:80").String(), "should match")
	assert.Equal(t, "http://example.com:80/test%20test",
		parseT(t, "http://example.com:80/test test").String(), "should match")
	assert.Equal(t, "http://example.com:80/test%20test",
		parseT(t, "http://example.com:80/test%20test").String(), "should match")
	assert.Equal(t, "http://example.com:80/test?key=value",
		parseT(t, "http://example.com:80/test?key=value").String(), "should match")

	// test invalid

	assert.NotEqual(t, parseTError("tcp"), nil, "should fail")
	assert.NotEqual(t, parseTError("tcp:"), nil, "should fail")
	assert.NotEqual(t, parseTError("tcp:0"), nil, "should fail")
	assert.NotEqual(t, parseTError("tcp:65536"), nil, "should fail")
}
