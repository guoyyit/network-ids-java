package com.github.guoyyit.networkidsjava.config;

import com.github.guoyyit.networkidsjava.ids.alert.Alert;
import com.github.guoyyit.networkidsjava.ids.alert.AlertSink;
import com.github.guoyyit.networkidsjava.ids.engine.IdsConfig;
import com.github.guoyyit.networkidsjava.ids.engine.IdsEngine;
import com.github.guoyyit.networkidsjava.ids.persistence.CheckpointStore;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Wires the in-process IDS engine and its persistence/sink beans.
 */
@Configuration
@EnableConfigurationProperties(IdsProperties.class)
public class IdsAutoConfiguration {

    @Bean
    public IdsConfig idsConfig(IdsProperties properties) {
        return new IdsConfig(
                properties.getMaxFlows(),
                properties.getIdleTimeoutMs(),
                properties.getClosedTimeoutMs(),
                properties.getMaxBufferedBytesPerDirection(),
                properties.getAggregationWindowMs(),
                properties.getContextRadius(),
                properties.getSnapshotInterval(),
                properties.getCheckpointDir(),
                properties.isPersistenceEnabled());
    }

    @Bean
    public CheckpointStore checkpointStore(IdsConfig config) {
        return config.persistenceEnabled() ? new CheckpointStore(config.checkpointDir()) : null;
    }

    @Bean
    public ListAlertSink alertSink() {
        return new ListAlertSink(new java.util.concurrent.ConcurrentHashMap<>());
    }

    @Bean
    public IdsEngine idsEngine(IdsConfig config,
                               ObjectProvider<CheckpointStore> storeProvider,
                               AlertSink sink) {
        return new IdsEngine(config, storeProvider.getIfAvailable(), sink);
    }

    /** Simple in-memory alert sink exposed for inspection via the controller. */
    public static final class ListAlertSink implements AlertSink {
        private final java.util.Map<String, Alert> byId;

        public ListAlertSink(java.util.Map<String, Alert> byId) {
            this.byId = byId;
        }

        @Override
        public synchronized void emit(Alert alert) {
            byId.put(alert.alertId(), alert);
        }

        public List<Alert> alerts() {
            return byId.values().stream()
                    .sorted(java.util.Comparator.comparing(Alert::firstTimestamp)
                            .thenComparing(Alert::alertId))
                    .toList();
        }
    }
}
