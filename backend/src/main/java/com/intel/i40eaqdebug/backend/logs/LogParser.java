package com.intel.i40eaqdebug.backend.logs;

import com.intel.i40eaqdebug.api.header.TimeStamp;
import com.intel.i40eaqdebug.api.logs.LogAdapter;
import com.intel.i40eaqdebug.api.logs.LogEntry;
import com.intel.i40eaqdebug.backend.logs.LogEntryImpl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser implements LogAdapter {

    /*
    Junk filter will take the format of time stamp and anything prefixed with i40e
    This will take flash_update_fail.log, normal_trace_dmesg.log, and normal_trace_syslog

    parsing of lanconf.log needs another regex because we cannot use i40e
        attempting to pick up the timestamp of lanconf.log through
        [0-9a-f]{3,} to avoid picking up military time.

        What we can use:
        AQ.+ can work for AQTX and AQ CM
        cookie.+
        param.+
        addr.+
        0x[0-9a-f]{4,}.+

    We should get desc and buffer for the readDiscreteEntries, cookies, params, and addr with the buffer content
    */
    Pattern BEGIN = Pattern.compile("desc and buffer");
    Pattern JUNK_FILTER = Pattern.compile("(((\\[([0-9]+)\\.([0-9]+)]))? (i40e .+))|([0-9a-f]{3,}\\:[0-9a-f]{3,}):\\s+(AQTX.+|AQ CMD.+|cookie.+|param.+|addr.+|0x[0-9a-f]{4}.+)");

    public Queue<LogEntry> getEntriesSequential(File f, int startIdx, int count) {
        try {
            return readDiscreteEntries(startIdx, count, new BufferedReader(new FileReader(f)));
        } catch (Exception e) {
            e.printStackTrace(); // TODO
            return new LinkedList<LogEntry>();
        }
    }

    public Queue<LogEntry> readDiscreteEntries(int startIdx, int count, BufferedReader reader) throws IOException {
        // Conditions Check
        if (startIdx < 0) {
            throw new IllegalArgumentException("Cannot read a negative entry index!");
        }
        if (count < 1) {
            throw new IllegalArgumentException("Cannot read 0 or negative entries!");
        }
        // TODO: possibly something more efficient than a skip read until we reach the startIdx?
        int readCount = -1;
        int currLineNumber = -1;
        int readLineNumber = 0;
        String line;
        boolean save = false;
        boolean flag = false; // Exiting read loop prior to end
        LinkedList<String> currEntry = new LinkedList<String>();
        LinkedHashMap<Integer, String[]> parsedEntries = new LinkedHashMap<Integer, String[]>();
        while ((line = reader.readLine()) != null) {
            readLineNumber++;
            // Check if it is a new discrete entry
            Matcher m = BEGIN.matcher(line);
            if (m.find()) {
                // New Discrete Entry
                readCount++; // Increment number of read entries
                if (readCount < startIdx) {
                    continue; // We haven't reached the part we are interested in yet so we skip until next entry
                }
                // Check if we already have a current Entry and add to parsed entries if so
                if (readLineNumber >= 0) { // We have an index that is non-zero -> we have read in something
                    if (currLineNumber != -1) { // Init value/we just reached first one
                        parsedEntries.put(currLineNumber, currEntry.toArray(new String[currEntry.size()]));
                    }
                    currLineNumber = readLineNumber; // Update the line for next read entry
                    currEntry.clear();
                }
                if (readCount == count) { // Reached the end of desired input
                    flag = true;
                    break;
                }
                // New discrete entry we want to read - update save flag if false
                save = true;
            } else {
                // Not a new discrete entry line
                if (save) {
                    currEntry.add(line);
                }
            }
        }
        if (!flag) { // Ended due to EOF
            parsedEntries.put(currLineNumber, currEntry.toArray(new String[currEntry.size()]));
        }
        Queue<LogEntry> ret = new LinkedList<LogEntry>();
        for (Map.Entry<Integer, String[]> entry : parsedEntries.entrySet()) {
            ret.add(produceEntry(entry.getKey(), entry.getValue()));
        }
        System.out.println(ret.size());
        return ret;
    }

    private LogEntry produceEntry(int lineNum, String[] lines) throws IOException {
        LinkedList<EntryRaw> out = new LinkedList<EntryRaw>();
        for (String logLine : lines) {
            Matcher m = JUNK_FILTER.matcher(logLine);
            if (m.find()) {
                String timesec = m.group(1);
                String timenano = m.group(2);
                String item = m.group(3);
                out.add(new EntryRaw(Long.valueOf(timesec), Long.valueOf(timenano), item));
            }
        }

        EntryRaw raw  = out.getFirst();

        TimeStamp stamp = new TimeStamp(raw.timestampSec, raw.timestampNano);
        String[] entraw = new String[out.size()];
        int i = 0;
        for (EntryRaw r : out) {
            entraw[i] = r.item;
            i++;
        }
        LogEntry ent = new LogEntryImpl(stamp, lineNum, entraw);
        System.out.println("Opcode: " + ent.getOpCode());
        return ent;
    }

    private class EntryRaw {
        long timestampSec;
        long timestampNano;
        String item;

        public EntryRaw(long timestampSec, long timestampNano, String item) {
            this.timestampSec = timestampSec;
            this.timestampNano = timestampNano;
            this.item = item;
        }
    }

}
