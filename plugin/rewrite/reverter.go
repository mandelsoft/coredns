package rewrite

import (
	"github.com/miekg/dns"
)

// ResponseRule contains a rule to rewrite a response with.
type ResponseRule interface {
	RewriteResponse(rr dns.RR)
}

type ResponseRules = []ResponseRule

// ResponseReverter reverses the operations done on the question section of a packet.
// This is need because the client will otherwise disregards the response, i.e.
// dig will complain with ';; Question section mismatch: got example.org/HINFO/IN'
type ResponseReverter struct {
	dns.ResponseWriter
	originalQuestion dns.Question
	ResponseRules    []ResponseRule
	noRestore        bool
}

// NewResponseReverter returns a pointer to a new ResponseReverter.
func NewResponseReverter(w dns.ResponseWriter, r *dns.Msg, noRestoreQuestion bool) *ResponseReverter {
	return &ResponseReverter{
		ResponseWriter:   w,
		originalQuestion: r.Question[0],
		noRestore:        noRestoreQuestion,
	}
}

// WriteMsg records the status code and calls the underlying ResponseWriter's WriteMsg method.
func (r *ResponseReverter) WriteMsg(res1 *dns.Msg) error {
	// Deep copy 'res' as to not (e.g). rewrite a message that's also stored in the cache.
	res := res1.Copy()

	if !r.noRestore {
		res.Question[0] = r.originalQuestion
	}
	if len(r.ResponseRules) > 0 {
		for _, rr := range res.Ns {
			r.rewriteResourceRecord(res, rr)
		}
		for _, rr := range res.Answer {
			r.rewriteResourceRecord(res, rr)
		}
		for _, rr := range res.Extra {
			r.rewriteResourceRecord(res, rr)
		}
	}
	return r.ResponseWriter.WriteMsg(res)
}

func (r *ResponseReverter) rewriteResourceRecord(res *dns.Msg, rr dns.RR) {
	for _, rule := range r.ResponseRules {
		rule.RewriteResponse(rr)
	}
}

// Write is a wrapper that records the size of the message that gets written.
func (r *ResponseReverter) Write(buf []byte) (int, error) {
	n, err := r.ResponseWriter.Write(buf)
	return n, err
}

func getRecordValueForRewrite(rr dns.RR) (name string) {
	switch rr.Header().Rrtype {
	case dns.TypeSRV:
		return rr.(*dns.SRV).Target
	case dns.TypeMX:
		return rr.(*dns.MX).Mx
	case dns.TypeCNAME:
		return rr.(*dns.CNAME).Target
	case dns.TypeNS:
		return rr.(*dns.NS).Ns
	case dns.TypeDNAME:
		return rr.(*dns.DNAME).Target
	case dns.TypeNAPTR:
		return rr.(*dns.NAPTR).Replacement
	case dns.TypeSOA:
		return rr.(*dns.SOA).Ns
	default:
		return ""
	}
}

func setRewrittenRecordValue(rr dns.RR, value string) {
	switch rr.Header().Rrtype {
	case dns.TypeSRV:
		rr.(*dns.SRV).Target = value
	case dns.TypeMX:
		rr.(*dns.MX).Mx = value
	case dns.TypeCNAME:
		rr.(*dns.CNAME).Target = value
	case dns.TypeNS:
		rr.(*dns.NS).Ns = value
	case dns.TypeDNAME:
		rr.(*dns.DNAME).Target = value
	case dns.TypeNAPTR:
		rr.(*dns.NAPTR).Replacement = value
	case dns.TypeSOA:
		rr.(*dns.SOA).Ns = value
	}
}
