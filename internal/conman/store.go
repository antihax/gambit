package conman

import (
	"bytes"
	"io/ioutil"
	"os"

	"github.com/antihax/gambit/internal/store"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// Store data if needed
func (s *ConnectionManager) store(filename, location string, data []byte) error {
	// write out

	if s.config.OutputFolder != "" {
		if err := ioutil.WriteFile(s.config.OutputFolder+"/"+location+"/"+filename, s.Sanitize(data), 0644); err != nil {
			s.logger.Debug().Err(err).Msg("error saving raw data")
		} else {
			s.knownHashes.Store(filename, true)
		}
	}
	// upload to s3
	if s.uploader != nil {
		if _, err := s.uploader.Upload(&s3manager.UploadInput{
			Bucket: aws.String(s.config.S3Bucket),
			Key:    aws.String(location + "/" + filename),
			Body:   ioutil.NopCloser(bytes.NewReader(s.Sanitize(data))),
		}); err != nil {
			s.logger.Debug().Err(err).Msg("error saving raw data")
			return err
		}
		s.knownHashes.Store(filename, true)

	}
	return nil
}

// read files to store
func (s *ConnectionManager) storePump() {
	for {
		file := <-s.storeChan
		if err := s.store(file.Filename, file.Location, file.Data); err != nil {
			s.storeChan <- file
		}
	}
}

func (s *ConnectionManager) setupStore() error {
	s.storeChan = make(chan store.File, 20)
	go s.storePump()

	// setup local storage
	if s.config.OutputFolder == "." {
		if pw, err := os.Getwd(); err != nil {
			return err
		} else {
			s.config.OutputFolder = pw + "/"
		}
	}
	if s.config.OutputFolder != "" {
		if err := os.Mkdir(s.config.OutputFolder+"raw", 0755); err != nil {
			return err
		}
		if err := os.Mkdir(s.config.OutputFolder+"sessions", 0755); err != nil {
			return err
		}
	}

	// setup s3 storage
	if s.config.S3Key != "" {
		s3Config := &aws.Config{
			Credentials:      credentials.NewStaticCredentials(s.config.S3KeyID, s.config.S3Key, ""),
			Endpoint:         aws.String(s.config.S3Endpoint),
			Region:           aws.String(s.config.S3Region),
			S3ForcePathStyle: aws.Bool(true),
		}
		sess := session.Must(session.NewSession(s3Config))
		s.uploader = s3manager.NewUploader(sess)
	}
	return nil
}
