package com.wizecore.graylog2.plugin;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.graylog2.plugin.Message;
import org.graylog2.syslog4j.SyslogIF;
import org.graylog2.syslog4j.impl.message.structured.StructuredSyslogMessage;
import org.graylog2.plugin.configuration.Configuration;

import com.google.common.base.Joiner;
import com.google.common.collect.Maps;

/**
 * Sends full message to Syslog.
 *
 * <165>1 2003-10-11T22:14:15.003Z mymachine.example.com
           evntslog - ID47 [exampleSDID@0 iut="3" eventSource=
           "Application" eventID="1011"] BOMAn application
           event log entry...

 */
public class FullSender implements MessageSender {
        private Logger log = Logger.getLogger(FullSender.class.getName());
        private boolean utf8bom = false;

        public FullSender() {
        }

        public FullSender(Configuration conf) {
            utf8bom = conf.getBoolean("utf8");
        }

        @Override
        public void send(SyslogIF syslog, int level, Message msg) {
                Map<String, String> sdParams = new HashMap<String, String>();
                Map<String, Object> fields = msg.getFields();
                for (String key: fields.keySet()) {
                        if (key != Message.FIELD_MESSAGE && key != Message.FIELD_FULL_MESSAGE && key != Message.FIELD_SOURCE) {
                                sdParams.put(key, fields.get(key).toString());
                        }
                }

                // http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
                // <name>@<enterpriseId>
                String sdId = "all@0";
                // log.info("Sending " + level + ", " + msg.getId() + ", " + msg.getSource() + ", " + sdId + "=" + sdParams + ", " + msg.getMessage());
                Map<String,Map<String,String>> sd = new HashMap<String, Map<String,String>>();
                sd.put(sdId, sdParams);

                String msgId = null;
                if (msgId == null) {
                        String source = msg.getSource();
                        if (source != null) {
                                msgId = source;
                        }
                }
                if (msgId == null) {
                        msgId = "-";
                }

                String sourceId = null;
                if (sourceId == null) {
                        Object facility = msg.getField("facility");
                        if (facility != null) {
                                sourceId = facility.toString();
                        }
                }
                if (sourceId == null) {
                        sourceId = "-";
                }

                String m = dumpMessage(msg);
                if(utf8bom) {
                        m = new String(SyslogOutput.BOM)  + m;
                }
                syslog.log(level, new StructuredSyslogMessage(msgId, sourceId, sd, m));
        }

        public static String dumpMessage(Message msg) {
                final StringBuilder sb = new StringBuilder();
                sb.append("source: ").append(msg.getField(Message.FIELD_SOURCE)).append(" | ");

                Object text = msg.getField(Message.FIELD_FULL_MESSAGE);
                if (text == null) {
                        text = msg.getField(Message.FIELD_MESSAGE);
                }
                final String message = text.toString().replaceAll("\\n", "").replaceAll("\\t", "");
                sb.append("message: ");
                sb.append(message);
                sb.append(" { ");

                final Map<String, Object> filteredFields = Maps.newHashMap(msg.getFields());
                filteredFields.remove(Message.FIELD_SOURCE);
                filteredFields.remove(Message.FIELD_MESSAGE);

                Joiner.on(" | ").withKeyValueSeparator(": ").appendTo(sb, filteredFields);

                sb.append(" }");
                return sb.toString();
        }
}
