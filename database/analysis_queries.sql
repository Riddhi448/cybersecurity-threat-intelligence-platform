SELECT
    label,
    COUNT(*) AS total_flows
FROM network_traffic
GROUP BY label
ORDER BY total_flows DESC;