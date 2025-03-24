package tracer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/wspr-ncsu/visiblev8/post-processor/core"
)

type Script struct {
	APIs []TraceEntry
	info *core.ScriptInfo
}

func NewScript(info *core.ScriptInfo) *Script {
	return &Script{
		APIs: make([]TraceEntry, 0),
		info: info,
	}
}

type TraceEntry struct {
	APIName   string   `json:api_name`
	Offset    int      `json:Offset`
	Arguments []string `json:Arguments`
	Mode      byte     `json:mode`
}

type flowAggregator struct {
	scriptList map[int]*Script
	lastAction TraceEntry
}

func NewTraceEntry(api string, offset int, args []string, mode byte) *TraceEntry {
	return &TraceEntry{
		APIName:   api,
		Offset:    offset,
		Arguments: args,
		Mode:      mode,
	}
}

func NewAggregator() (core.Aggregator, error) {
	return &flowAggregator{
		scriptList: make(map[int]*Script),
	}, nil
}

func (agg *flowAggregator) IngestRecord(ctx *core.ExecutionContext, lineNumber int, op byte, fields []string) error {
	if (ctx.Script != nil) && !ctx.Script.VisibleV8 && (ctx.Origin.Origin != "") {
		offset, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("%d: invalid script offset '%s'", lineNumber, fields[0])
		}
		var receiver, member string
		var args []string = make([]string, 0)
		switch op {
		case 'g', 's':
			receiver, _ = core.StripCurlies(fields[1])
			member, _ = core.StripQuotes(fields[2])
			if len(fields) > 3 {
				args = append(args, fields[2:]...)
			}
		case 'n':
			receiver, _ = core.StripCurlies(fields[1])
			receiver = strings.TrimPrefix(receiver, "%")
			if len(fields) > 2 {
				args = append(args, fields[1:]...)
			}
		case 'c':
			receiver, _ = core.StripCurlies(fields[2])
			member, _ = core.StripQuotes(fields[1])
			if len(fields) > 3 {
				args = append(args, fields[2:]...)
			}
			member = strings.TrimPrefix(member, "%")
		default:
			return fmt.Errorf("%d: invalid mode '%c'; fields: %v", lineNumber, op, fields)
		}

		if core.FilterName(member) {
			// We have some names (V8 special cases, numeric indices) that are never useful
			return nil
		}

		if strings.Contains(receiver, ",") {
			receiver = strings.Split(receiver, ",")[1]
		}

		var fullName string
		if member != "" {
			fullName = fmt.Sprintf("%s.%s", receiver, member)
		} else {
			fullName = receiver
		}

		script, ok := agg.scriptList[ctx.Script.ID]

		if !ok {
			script = NewScript(ctx.Script)
			agg.scriptList[ctx.Script.ID] = script
		}

		currentAction := NewTraceEntry(fullName, offset, args, op)

		if agg.lastAction.APIName == currentAction.APIName && op == 'c' && agg.lastAction.Mode == 'g' {
			script.APIs = script.APIs[:len(script.APIs)-1]
		}

		script.APIs = append(script.APIs, *currentAction)
	}

	return nil
}

var tracerScriptFields = [...]string{
	"sha256",
	"code",
}

var tracerTracesFields = [...]string{
	"isolate",
	"visiblev8",
	"sha256",
	"first_origin",
	"url",
	"apis",
	"unique_id",
	"evaled_by",
}

func (agg *flowAggregator) DumpToStream(ctx *core.AggregationContext, stream io.Writer) error {
	jstream := json.NewEncoder(stream)

	for _, script := range agg.scriptList {

		var evaledById uuid.UUID = uuid.Nil
		if script.info.EvaledBy != nil {
			evaledById = script.info.EvaledBy.UniqueIdentifier
		}
		jstream.Encode(core.JSONArray{"tracer.scripts", core.JSONObject{
			"SHA256": script.info.CodeHash.SHA2,
			"Code":   script.info.Code,
		}})

		jstream.Encode(core.JSONArray{"tracer.traces", core.JSONObject{
			"ID":          script.info.UniqueIdentifier,
			"Isolate":     script.info.Isolate.ID,
			"IsVisibleV8": script.info.VisibleV8,
			"FirstOrigin": script.info.FirstOrigin,
			"URL":         script.info.URL,
			"IsEvaledBy":  evaledById,
			"APIs":        script.APIs,
		}})
	}

	return nil
}

func (agg *flowAggregator) DumpToPostgresql(ctx *core.AggregationContext, sqlDb *sql.DB) error {

	txn, err := sqlDb.Begin()
	if err != nil {
		return err
	}

	stmt_script, err := txn.Prepare(pq.CopyIn("tracer.scripts", tracerScriptFields[:]...))
	if err != nil {
		txn.Rollback()
		return err
	}

	stmt_traces, err := txn.Prepare(pq.CopyIn("tracer.traces", tracerTracesFields[:]...))
	if err != nil {
		txn.Rollback()
		return err
	}

	log.Printf("scriptFlow: %d scripts analysed", len(agg.scriptList))

	for _, script := range agg.scriptList {
		var evaledById uuid.UUID = uuid.Nil
		if script.info.EvaledBy != nil {
			evaledById = script.info.EvaledBy.UniqueIdentifier
		}

		_, err = stmt_script.Exec(
			script.info.Code,
			script.info.CodeHash.SHA2[:],
		)
		if err != nil {
			txn.Rollback() // Might have been duplicate, so just save trace?
		}

		_, err = stmt_traces.Exec(
			script.info.Isolate,
			script.info.VisibleV8,
			script.info.CodeHash.SHA2[:],
			script.info.URL,
			script.APIs,
			script.info.UniqueIdentifier,
			evaledById,
		)

		if err != nil {
			txn.Rollback()
			return err
		}

	}

	err = stmt_script.Close()
	if err != nil {
		txn.Rollback()
		return err
	}
	err = stmt_traces.Close()
	if err != nil {
		txn.Rollback()
		return err
	}
	err = txn.Commit()
	if err != nil {
		return err
	}

	return nil
}
