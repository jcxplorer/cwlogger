package cwlogger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
)

type LogGroup struct {
	ErrorReporter func(err error)

	name    *string
	svc     *cloudwatchlogs.CloudWatchLogs
	streams *logStreams
	prefix  string
	batcher *batcher
	wg      sync.WaitGroup
	done    chan bool
}

func NewLogGroup(name string, client *cloudwatchlogs.CloudWatchLogs) (*LogGroup, error) {
	lg := &LogGroup{
		ErrorReporter: noopErrorReporter,
		name:          &name,
		svc:           client,
		prefix:        randomHex(32),
		batcher:       newBatcher(),
		done:          make(chan bool),
	}

	lg.streams = newLogStreams(lg)

	if err := lg.createIfNotExists(); err != nil {
		return nil, err
	}
	if err := lg.streams.new(); err != nil {
		return nil, err
	}

	go lg.worker()

	return lg, nil
}

func (lg *LogGroup) Log(t time.Time, s string) {
	lg.wg.Add(1)
	go func() {
		lg.batcher.input <- &cloudwatchlogs.InputLogEvent{
			Message:   &s,
			Timestamp: aws.Int64(t.UnixNano() / int64(time.Millisecond)),
		}
		lg.wg.Done()
	}()
}

func (lg *LogGroup) Close() {
	lg.wg.Wait()       // wait for all log entries to be accepted
	lg.batcher.flush() // wait for all log entries to be batched
	<-lg.done          // wait for all batches to be processed
	lg.streams.flush() // wait for all batches to be sent to CloudWatch Logs
}

func (lg *LogGroup) worker() {
	for batch := range lg.batcher.output {
		lg.streams.write(batch)
	}
	lg.done <- true
}

func (lg *LogGroup) createIfNotExists() error {
	_, err := lg.svc.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: lg.name,
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == cloudwatchlogs.ErrCodeResourceAlreadyExistsException {
				return nil
			}
		}
	}
	return err
}

type writeError struct {
	batch  []*cloudwatchlogs.InputLogEvent
	stream *logStream
	err    error
}

type logStreams struct {
	logGroup *LogGroup
	streams  []*logStream
	writers  map[*logStream]chan []*cloudwatchlogs.InputLogEvent
	writes   chan []*cloudwatchlogs.InputLogEvent
	errors   chan *writeError
	wg       sync.WaitGroup
}

func newLogStreams(lg *LogGroup) *logStreams {
	streams := &logStreams{
		logGroup: lg,
		streams:  []*logStream{},
		writers:  make(map[*logStream]chan []*cloudwatchlogs.InputLogEvent),
		writes:   make(chan []*cloudwatchlogs.InputLogEvent),
		errors:   make(chan *writeError),
	}
	go streams.coordinator()
	return streams
}

func (ls *logStreams) new() error {
	name := ls.logGroup.prefix + "." + strconv.Itoa(len(ls.streams))
	stream := &logStream{
		name:     &name,
		logGroup: ls.logGroup,
	}

	err := stream.create()
	if err != nil {
		return err
	}

	ls.streams = append(ls.streams, stream)
	ls.writers[stream] = make(chan []*cloudwatchlogs.InputLogEvent)
	go ls.writer(stream)

	return nil
}

func (ls *logStreams) write(b []*cloudwatchlogs.InputLogEvent) {
	ls.wg.Add(1)
	go func() {
		ls.writes <- b
	}()
}

func (ls *logStreams) writer(stream *logStream) {
	for batch := range ls.writers[stream] {
		batch := batch // create new instance of batch for the goroutine
		err := stream.write(batch)
		if err != nil {
			go func() {
				ls.errors <- &writeError{
					batch:  batch,
					stream: stream,
					err:    err,
				}
			}()
		} else {
			ls.wg.Done()
		}
	}
}

func (ls *logStreams) coordinator() {
	i := 0
	for {
		select {
		case batch := <-ls.writes:
			i = (i + 1) % len(ls.streams)
			stream := ls.streams[i]
			ls.writers[stream] <- batch
		case err := <-ls.errors:
			ls.handle(err)
		}
	}
}

func (ls *logStreams) handle(writeErr *writeError) {
	if isErrorCode(writeErr.err, errCodeThrottlingException) {
		ls.new()
	}
	if shouldRetry(writeErr.err) {
		go func() {
			ls.writes <- writeErr.batch
		}()
	} else {
		ls.wg.Done()
		ls.logGroup.ErrorReporter(writeErr.err)
	}
}

func (ls *logStreams) flush() {
	ls.wg.Wait()
}

type logStream struct {
	name          *string
	logGroup      *LogGroup
	sequenceToken *string
}

func (ls *logStream) create() error {
	_, err := ls.logGroup.svc.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  ls.logGroup.name,
		LogStreamName: ls.name,
	})
	return err
}

func (ls *logStream) write(b []*cloudwatchlogs.InputLogEvent) error {
	req, _ := ls.logGroup.svc.PutLogEventsRequest(&cloudwatchlogs.PutLogEventsInput{
		LogGroupName:  ls.logGroup.name,
		LogStreamName: ls.name,
		LogEvents:     b,
		SequenceToken: ls.sequenceToken,
	})

	req.Sign()
	resp, err := ls.logGroup.svc.Client.Config.HTTPClient.Do(req.HTTPRequest)

	if err != nil {
		return err
	}

	dec := json.NewDecoder(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data putLogEventsSuccessResponse
		if err := dec.Decode(&data); err != nil {
			return err
		}
		ls.sequenceToken = &data.NextSequenceToken
	} else {
		var data putLogEventsErrorResponse
		if err := dec.Decode(&data); err != nil {
			return err
		}
		if data.ExpectedSequenceToken != nil {
			ls.sequenceToken = data.ExpectedSequenceToken
		}
		return Error{
			Code:    data.Code,
			Message: data.Message,
		}
	}

	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
