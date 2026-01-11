package core

import "encoding/xml"

const s3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type ListAllMyBucketsOwner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type ListAllMyBucketsEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListAllMyBucketsResult represents the XML response for the S3 ListBuckets API.
type ListAllMyBucketsResult struct {
	XMLName xml.Name                `xml:"ListAllMyBucketsResult"`
	XMLNS   string                  `xml:"xmlns,attr"`
	Owner   ListAllMyBucketsOwner   `xml:"Owner"`
	Buckets []ListAllMyBucketsEntry `xml:"Buckets>Bucket"`
}

// CommonPrefix represents a single common prefix entry in a ListBucketResult.
// It is used to model "directories" when a delimiter such as "/" is used.
type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ListBucketResult represents the XML response for the S3 ListObjects API.
type ListBucketResult struct {
	XMLName        xml.Name        `xml:"ListBucketResult"`
	XMLNS          string          `xml:"xmlns,attr"`
	Name           string          `xml:"Name"`
	Prefix         string          `xml:"Prefix"`
	Delimiter      string          `xml:"Delimiter,omitempty"`
	MaxKeys        int             `xml:"MaxKeys"`
	IsTruncated    bool            `xml:"IsTruncated"`
	Contents       []ObjectSummary `xml:"Contents"`
	CommonPrefixes []CommonPrefix  `xml:"CommonPrefixes,omitempty"`
}

// ListBucketResultV2 represents the XML response for the S3 ListObjectsV2
// API.
type ListBucketResultV2 struct {
	XMLName               xml.Name        `xml:"ListBucketResult"`
	XMLNS                 string          `xml:"xmlns,attr"`
	Name                  string          `xml:"Name"`
	Prefix                string          `xml:"Prefix"`
	Delimiter             string          `xml:"Delimiter,omitempty"`
	KeyCount              int             `xml:"KeyCount"`
	MaxKeys               int             `xml:"MaxKeys"`
	IsTruncated           bool            `xml:"IsTruncated"`
	ContinuationToken     string          `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string          `xml:"NextContinuationToken,omitempty"`
	StartAfter            string          `xml:"StartAfter,omitempty"`
	Contents              []ObjectSummary `xml:"Contents"`
	CommonPrefixes        []CommonPrefix  `xml:"CommonPrefixes,omitempty"`
}

// ObjectSummary is a single entry in a ListBucketResult.
type ObjectSummary struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type S3Error struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource"`
}

type LocationConstraint struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	XMLNS   string   `xml:"xmlns,attr"`
	Region  string   `xml:",chardata"`
}

type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	XMLNS        string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// Tag represents a single key/value tag entry.
type Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// Tagging represents the XML payload for bucket tagging APIs.
type Tagging struct {
	XMLName xml.Name `xml:"Tagging"`
	XMLNS   string   `xml:"xmlns,attr,omitempty"`
	TagSet  []Tag    `xml:"TagSet>Tag"`
}
