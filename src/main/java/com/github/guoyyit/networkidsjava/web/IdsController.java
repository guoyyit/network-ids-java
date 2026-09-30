package com.github.guoyyit.networkidsjava.web;

import com.github.guoyyit.networkidsjava.config.IdsAutoConfiguration;
import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.ids.model.Packet;
import com.github.guoyyit.networkidsjava.ids.model.TcpFlags;
import com.github.guoyyit.networkidsjava.ids.rule.Rule;
import com.github.guoyyit.networkidsjava.ids.rule.RuleParser;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Local-only HTTP interface for packet injection, dynamic rule management,
 * status inspection and alert retrieval. No external services are required.
 */
@RestController
@RequestMapping("/ids")
public class IdsController {

    private final IdsEngine engine;
    private final IdsAutoConfiguration.ListAlertSink sink;

    public IdsController(IdsEngine engine, IdsAutoConfiguration.ListAlertSink sink) {
        this.engine = engine;
        this.sink = sink;
    }

    @PostMapping("/packets")
    public ResponseEntity<List<Alert>> inject(@RequestBody PacketRequest request) {
        if (request.srcPort <= 0 || request.srcPort > 65535
                || request.dstPort <= 0 || request.dstPort > 65535) {
            return ResponseEntity.badRequest().build();
        }
        byte[] payload = request.payloadHex == null || request.payloadHex.isBlank()
                ? new byte[0]
                : HexFormat.of().parseHex(request.payloadHex.replaceAll("\\s+", ""));
        Packet packet = new Packet(request.timestamp, request.srcIp, request.srcPort,
                request.dstIp, request.dstPort, request.seq, request.ack,
                parseFlags(request.flags), payload);
        return ResponseEntity.ok(engine.processPacket(packet));
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of(
                "activeFlows", engine.activeFlowCount(),
                "lastCommittedPosition", engine.lastCommittedPosition(),
                "rules", engine.rules().size());
    }

    @GetMapping("/rules")
    public List<Rule> rules() {
        return engine.rules();
    }

    @PostMapping("/rules")
    public ResponseEntity<String> addRule(@RequestBody String ruleLine) {
        try {
            Rule rule = RuleParser.parseLine(ruleLine);
            if (rule == null) {
                return ResponseEntity.badRequest().body("empty rule");
            }
            engine.addRule(rule);
            return ResponseEntity.ok(rule.id());
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/rules/{ruleId}")
    public Map<String, Object> removeRule(@PathVariable String ruleId) {
        return Map.of("removed", engine.removeRule(ruleId));
    }

    @GetMapping("/alerts")
    public List<Alert> alerts() {
        return sink.alerts();
    }

    private static int parseFlags(String flags) {
        if (flags == null || flags.isBlank()) {
            return 0;
        }
        try {
            return flags.startsWith("0x") || flags.matches("\\d+")
                    ? Integer.decode(flags.trim())
                    : TcpFlags.parse(flags);
        } catch (NumberFormatException e) {
            return TcpFlags.parse(flags);
        }
    }

    /** Packet injection request body. */
    public static final class PacketRequest {
        public long timestamp;
        public String srcIp;
        public int srcPort;
        public String dstIp;
        public int dstPort;
        public long seq;
        public long ack;
        public String flags;
        public String payloadHex;
    }

}
