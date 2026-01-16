package core

import "encoding/xml"

const S3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListAllMyBucketsResult represents the XML response for the S3 ListBuckets API.
type ListAllMyBucketsResult struct {
	XMLName xml.Name      `xml:"ListAllMyBucketsResult"`
	XMLNS   string        `xml:"xmlns,attr"`
	Owner   Owner         `xml:"Owner"`
	Buckets []BucketEntry `xml:"Buckets>Bucket"`
}

// CommonPrefix represents a single common prefix entry in a ListBucketResultV1.
// It is used to model "directories" when a delimiter such as "/" is used.
type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// ListBucketResultV1 represents the XML response for the S3 ListObjects API.
type ListBucketResultV1 struct {
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

// ListBucketResultV2 represents the XML response for the S3 ListBucketResultV2
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

// InitiateMultipartUploadResult represents the XML response for the
// CreateMultipartUpload (InitiateMultipartUpload) API.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CompletedPart represents a single part entry in a CompleteMultipartUpload
// request body.
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// CompleteMultipartUpload represents the XML payload sent to the
// CompleteMultipartUpload API.
type CompleteMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompleteMultipartUploadResult represents the XML response for the
// CompleteMultipartUpload API.
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// ListPartsPart represents a single part entry in a ListPartsResult
// response.
type ListPartsPart struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// ListPartsResult represents the XML response for the ListParts API.
type ListPartsResult struct {
	XMLName              xml.Name        `xml:"ListPartsResult"`
	XMLNS                string          `xml:"xmlns,attr"`
	Bucket               string          `xml:"Bucket"`
	Key                  string          `xml:"Key"`
	UploadID             string          `xml:"UploadId"`
	PartNumberMarker     int             `xml:"PartNumberMarker"`
	NextPartNumberMarker int             `xml:"NextPartNumberMarker"`
	MaxParts             int             `xml:"MaxParts"`
	IsTruncated          bool            `xml:"IsTruncated"`
	Parts                []ListPartsPart `xml:"Part"`
}

// MultipartUploadInfo represents a single in-progress multipart upload entry
// in a ListMultipartUploadsResult response.
type MultipartUploadInfo struct {
	Key          string `xml:"Key"`
	UploadID     string `xml:"UploadId"`
	Initiator    Owner  `xml:"Initiator"`
	Owner        Owner  `xml:"Owner"`
	StorageClass string `xml:"StorageClass"`
	Initiated    string `xml:"Initiated"`
}

// ListMultipartUploadsResult represents the XML response for the
// ListMultipartUploads API: GET /bucket?uploads
type ListMultipartUploadsResult struct {
	XMLName            xml.Name              `xml:"ListMultipartUploadsResult"`
	XMLNS              string                `xml:"xmlns,attr"`
	Bucket             string                `xml:"Bucket"`
	KeyMarker          string                `xml:"KeyMarker"`
	UploadIDMarker     string                `xml:"UploadIdMarker"`
	NextKeyMarker      string                `xml:"NextKeyMarker"`
	NextUploadIDMarker string                `xml:"NextUploadIdMarker"`
	MaxUploads         int                   `xml:"MaxUploads"`
	IsTruncated        bool                  `xml:"IsTruncated"`
	Prefix             string                `xml:"Prefix"`
	Delimiter          string                `xml:"Delimiter,omitempty"`
	CommonPrefixes     []CommonPrefix        `xml:"CommonPrefixes,omitempty"`
	Uploads            []MultipartUploadInfo `xml:"Upload"`
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

// DeleteObject represents a single object entry in a multi-object delete
// request or response.
type DeleteObject struct {
	Key string `xml:"Key"`
}

// DeleteObjectsRequest represents the XML payload for the S3 DeleteObjects
// API: POST /bucket?delete
type DeleteObjectsRequest struct {
	XMLName xml.Name       `xml:"Delete"`
	Objects []DeleteObject `xml:"Object"`
}

// DeletedObject represents a successfully deleted object entry in a
// DeleteResult response.
type DeletedObject struct {
	Key string `xml:"Key"`
}

// DeleteResult represents the XML response for the DeleteObjects API.
type DeleteResult struct {
	XMLName xml.Name        `xml:"DeleteResult"`
	XMLNS   string          `xml:"xmlns,attr"`
	Deleted []DeletedObject `xml:"Deleted"`
}
