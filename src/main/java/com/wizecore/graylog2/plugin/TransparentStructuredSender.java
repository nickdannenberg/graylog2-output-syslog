package com.wizecore.graylog2.plugin;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.util.Arrays;
import java.util.List;

import org.graylog2.plugin.Message;
import org.graylog2.syslog4j.SyslogIF;
import org.graylog2.syslog4j.SyslogConfigIF;
import org.graylog2.syslog4j.SyslogMessageProcessorIF;
import org.graylog2.syslog4j.impl.message.processor.structured.StructuredSyslogMessageProcessor;
import org.graylog2.syslog4j.impl.message.structured.StructuredSyslogMessage;
import org.graylog2.syslog4j.SyslogConstants;
import org.graylog2.plugin.configuration.Configuration;
import org.apache.commons.lang3.StringUtils;

/**
 * https://tools.ietf.org/html/rfc5424
 *
 * <165>1 2003-10-11T22:14:15.003Z mymachine.example.com
           evntslog - ID47 [exampleSDID@0 iut="3" eventSource=
           "Application" eventID="1011"] BOMAn application
           event log entry...

 */
public class TransparentStructuredSender implements MessageSender {
	private Logger log = Logger.getLogger(StructuredSender.class.getName());
        private boolean utf8bom = false;
        private static final List<String> ignored_fields = Arrays.asList( Message.FIELD_MESSAGE,
                                                                          Message.FIELD_FULL_MESSAGE,
                                                                          Message.FIELD_SOURCE,
                                                                          Message.FIELD_GL2_MESSAGE_ID,
                                                                          //Message.FIELD_ID,
                                                                          Message.FIELD_TIMESTAMP,
                                                                          "application_name",
                                                                          "process_id",
                                                                          "facility_num");

        public TransparentStructuredSender() {
        }

        public TransparentStructuredSender(Configuration conf) {
                utf8bom = conf.getBoolean("utf8");
        }

	@Override
	public void send(SyslogIF syslog, int level, Message msg) {
		Map<String, String> sdParams = new HashMap<String, String>();
		Map<String, Object> fields = msg.getFields();

		for (String key: fields.keySet()) {
                    if ( !ignored_fields.contains(key)) {
                        sdParams.put(key, fields.get(key).toString());
                    }
		}

		// http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
		// <name>@<enterpriseId>
		String sdId = "all@0";
		// log.info("Sending " + level + ", " + msg.getId() + ", " + msg.getSource() + ", " + sdId + "=" + sdParams + ", " + msg.getMessage());
		Map<String,Map<String,String>> sd = new HashMap<String, Map<String,String>>();
		sd.put(sdId, sdParams);

		String msgId = safeGetString(fields, Message.FIELD_GL2_MESSAGE_ID);
                String source = safeGetString(fields, Message.FIELD_SOURCE);
                String app = safeGetString(fields, "application_name");
                String procId = safeGetString(fields, "process_id");
                String facility = safeGetString(fields, "facility_num");
                int facility_num = SyslogConstants.FACILITY_USER;
                try {
                    // syslog4j stores facilities bit-shifted (to have less computation when creating syslog priority field?)
                    facility_num = Integer.parseInt(facility) << 3;
                } catch( NumberFormatException e) {
                    // don't care
                }

                SyslogConfigIF cfg = syslog.getConfig();
                cfg.setFacility(facility_num);
                cfg.setLocalName(source);
                StructuredSyslogMessageProcessor processor = (StructuredSyslogMessageProcessor) syslog.getStructuredMessageProcessor();
                processor.setApplicationName(app);
                processor.setProcessId(procId);

                // log.info("Syslog output sending " +
                //          " level:" + level +
                //          " facility_num: " + facility_num +
                //          " facility: " + facility +
                //          " source: " + source +
                //          " app: " + app +
                //          " procId: " + procId +
                //          " msgId: " + msgId +
                //          "."
                //     );
                String m = msg.getMessage();
                if(utf8bom) {
                        m = new String(SyslogOutput.BOM)  + m;
                }
		syslog.log(level, new StructuredSyslogMessage(msgId, procId, sd, m), msg.getTimestamp().toDate());
	}

    private String safeGetString(Map<String, Object> fields, String key) {
        if(fields.containsKey(key)) {
            String value = fields.get(key).toString();
            if (StringUtils.isBlank(value)) {
                return SyslogConstants.STRUCTURED_DATA_NILVALUE;
            } else {
                return value;
            }
        } else {
            return SyslogConstants.STRUCTURED_DATA_NILVALUE;
        }
    }
}


