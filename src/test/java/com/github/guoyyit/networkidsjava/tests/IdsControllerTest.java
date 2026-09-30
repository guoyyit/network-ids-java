package com.github.guoyyit.networkidsjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "ids.persistence-enabled=false",
        "ids.max-flows=8",
        "ids.aggregation-window-ms=1000"
})
@AutoConfigureMockMvc
class IdsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void managesRulesInjectsPacketAndReportsStatus() throws Exception {
        mockMvc.perform(post("/ids/rules").content("evil: 73 65 63 72 65 74"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/ids/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value("evil"));

        String syn = """
                {"timestamp":1,"srcIp":"10.0.0.1","srcPort":1000,
                 "dstIp":"10.0.0.2","dstPort":80,"seq":1000,"ack":0,"flags":"S"}
                """;
        mockMvc.perform(post("/ids/packets").contentType("application/json").content(syn))
                .andExpect(status().isOk());
        String synAck = """
                {"timestamp":2,"srcIp":"10.0.0.2","srcPort":80,
                 "dstIp":"10.0.0.1","dstPort":1000,"seq":5000,"ack":0,"flags":"SA"}
                """;
        mockMvc.perform(post("/ids/packets").contentType("application/json").content(synAck))
                .andExpect(status().isOk());
        String data = """
                {"timestamp":3,"srcIp":"10.0.0.1","srcPort":1000,
                 "dstIp":"10.0.0.2","dstPort":80,"seq":1001,"ack":0,
                 "flags":"PA","payloadHex":"736563726574"}
                """;
        mockMvc.perform(post("/ids/packets").contentType("application/json").content(data))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].ruleId").value("evil"));

        mockMvc.perform(get("/ids/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rules").value(1));

        mockMvc.perform(delete("/ids/rules/evil"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.removed").value(true));
    }

    @Test
    void rejectsInvalidPorts() throws Exception {
        String bad = """
                {"timestamp":1,"srcIp":"10.0.0.1","srcPort":0,
                 "dstIp":"10.0.0.2","dstPort":80,"flags":"S"}
                """;
        mockMvc.perform(post("/ids/packets").contentType("application/json").content(bad))
                .andExpect(status().isBadRequest());
    }
}
