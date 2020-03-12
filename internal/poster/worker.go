package poster

import (
	"bytes"
	"context"
	log "github.com/sirupsen/logrus"
	"runtime"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

const MAXWORKERS int = 2

type Worker struct {
	Ctx context.Context
	HttpClient *retryablehttp.Client
	EventChannel <-chan string
	URL string
}

func NewWorker(ctx context.Context, eventChannel <-chan string, url string, index int) *Worker {
	obj := Worker{
		ctx,
		retryablehttp.NewClient(),
		eventChannel,
		url,
	}
	obj.HttpClient.Logger = log.WithField("worker_id", index)

	return &obj
}

func (w Worker) Run() {
	log.Debugf("Running worker")
	for {
		select {
			case <-w.Ctx.Done():
				log.Debug("Stopping worker")
				return
			case jsondata := <-w.EventChannel:

				log.Debug("printing %v", jsondata)
				resp, err := w.HttpClient.Post(w.URL, "application/json", bytes.NewBufferString(jsondata))
				if err != nil {
					log.Debug("Got error")
					log.Debug(err)
				} else {
					_ = resp.Body.Close()
				}
		}
	}
}


type WorkerPool struct {
	Ctx context.Context
	CtxCancel context.CancelFunc
	workers []*Worker
}

func NewWorkerPool(eventChannel <-chan string, workers int, url string) *WorkerPool {
	if workers == 0 {
		workers = runtime.NumCPU()
	}

	if workers > MAXWORKERS {
		workers = MAXWORKERS
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	obj := WorkerPool{
		ctx,
		cancel,
		make([]*Worker, workers),
	}
	
	// Create workers
	for i := 0; i < workers; i++ {
		obj.workers[i] = NewWorker(ctx, eventChannel, url, i)
		log.Debugf("Created worker %v", i)
		go obj.workers[i].Run()
	}

	return &obj
}

func (p WorkerPool) Close() {
	p.CtxCancel()
	<-time.After(500 * time.Millisecond)
}