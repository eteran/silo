package silo

import "encoding/xml"

const s3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// ListAllMyBucketsResult represents the XML response for the S3 ListBuckets API.
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	XMLNS   string   `xml:"xmlns,attr"`
	Owner   struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	Buckets []struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	} `xml:"Buckets>Bucket"`
}

// ListBucketResult represents the XML response for the S3 ListObjects API.
type ListBucketResult struct {
	XMLName     xml.Name        `xml:"ListBucketResult"`
	XMLNS       string          `xml:"xmlns,attr"`
	Name        string          `xml:"Name"`
	Prefix      string          `xml:"Prefix"`
	MaxKeys     int             `xml:"MaxKeys"`
	IsTruncated bool            `xml:"IsTruncated"`
	Contents    []ObjectSummary `xml:"Contents"`
}

// ListBucketResultV2 represents the XML response for the S3 ListObjectsV2
// API.
type ListBucketResultV2 struct {
	XMLName               xml.Name        `xml:"ListBucketResult"`
	XMLNS                 string          `xml:"xmlns,attr"`
	Name                  string          `xml:"Name"`
	Prefix                string          `xml:"Prefix"`
	KeyCount              int             `xml:"KeyCount"`
	MaxKeys               int             `xml:"MaxKeys"`
	IsTruncated           bool            `xml:"IsTruncated"`
	ContinuationToken     string          `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string          `xml:"NextContinuationToken,omitempty"`
	StartAfter            string          `xml:"StartAfter,omitempty"`
	Contents              []ObjectSummary `xml:"Contents"`
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
