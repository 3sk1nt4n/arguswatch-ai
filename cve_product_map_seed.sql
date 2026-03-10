-- V16.4.5: Seed cve_product_map with REAL modern products matching customer tech_stack assets
-- This maps CISA KEV CVEs to the products customers actually run

-- First check current table structure
-- Then insert mappings for products in customer tech_stacks:
-- Exchange Server, Kubernetes, Elasticsearch, Redis, Postgresql, Mongodb, Esxi,
-- Vcenter Server, Ios Xe, Junos, Confluence Server, Jira Server, Gitlab, Jenkins,
-- Oracle, Java, Go, MySQL, Ruby on Rails, PHP, Apache, Horizon

INSERT INTO cve_product_map (cve_id, product_name, vendor, version_range) VALUES
-- Exchange Server (PAYPAL, apple)
('CVE-2021-26855', 'Exchange Server', 'Microsoft', '< 15.2.792.10'),
('CVE-2021-26857', 'Exchange Server', 'Microsoft', '< 15.2.792.10'),
('CVE-2021-26858', 'Exchange Server', 'Microsoft', '< 15.2.792.10'),
('CVE-2021-27065', 'Exchange Server', 'Microsoft', '< 15.2.792.10'),
('CVE-2021-34473', 'Exchange Server', 'Microsoft', '< 15.2.922.7'),
('CVE-2021-34523', 'Exchange Server', 'Microsoft', '< 15.2.922.7'),
('CVE-2021-31207', 'Exchange Server', 'Microsoft', '< 15.2.922.7'),
('CVE-2020-0688', 'Exchange Server', 'Microsoft', '< 15.2.721.2'),
('CVE-2020-17144', 'Exchange Server', 'Microsoft', '< 15.2.792.3'),
-- Kubernetes (PAYPAL, apple)
('CVE-2018-1002105', 'Kubernetes', 'Kubernetes', '< 1.10.11'),
('CVE-2019-11253', 'Kubernetes', 'Kubernetes', '< 1.13.12'),
('CVE-2020-8554', 'Kubernetes', 'Kubernetes', '< 1.21.0'),
('CVE-2021-25741', 'Kubernetes', 'Kubernetes', '< 1.22.2'),
('CVE-2024-9486', 'Kubernetes', 'Kubernetes', ''),
-- Elasticsearch (PAYPAL, apple)
('CVE-2021-22145', 'Elasticsearch', 'Elastic', '< 7.13.4'),
('CVE-2021-22144', 'Elasticsearch', 'Elastic', '< 7.13.4'),
('CVE-2015-1427', 'Elasticsearch', 'Elastic', '< 1.3.8'),
-- Redis (PAYPAL, apple)
('CVE-2022-0543', 'Redis', 'Redis', '< 6.2.7'),
('CVE-2021-32761', 'Redis', 'Redis', '< 6.2.5'),
('CVE-2021-32675', 'Redis', 'Redis', '< 6.2.6'),
-- PostgreSQL (PAYPAL, apple)
('CVE-2023-5868', 'Postgresql', 'PostgreSQL', '< 16.1'),
('CVE-2023-5869', 'Postgresql', 'PostgreSQL', '< 16.1'),
('CVE-2023-5870', 'Postgresql', 'PostgreSQL', '< 16.1'),
-- MongoDB (PAYPAL, apple)
('CVE-2021-20330', 'Mongodb', 'MongoDB', '< 4.4.4'),
-- ESXi (PAYPAL, apple)
('CVE-2021-21985', 'Vcenter Server', 'VMware', '< 6.7.0'),
('CVE-2021-21972', 'Vcenter Server', 'VMware', '< 6.7.0'),
('CVE-2021-22005', 'Vcenter Server', 'VMware', '< 7.0.2'),
('CVE-2020-3952', 'Vcenter Server', 'VMware', '< 6.7.0'),
('CVE-2019-5544', 'Esxi', 'VMware', '< 6.7.0'),
('CVE-2020-3992', 'Esxi', 'VMware', '< 7.0.0'),
('CVE-2020-3950', 'Esxi', 'VMware', ''),
-- Horizon (PAYPAL, apple)  
('CVE-2022-22954', 'Horizon', 'VMware', '< 8.0.0'),
('CVE-2022-22960', 'Horizon', 'VMware', '< 8.0.0'),
-- Confluence Server (PAYPAL, apple)
('CVE-2022-26134', 'Confluence Server', 'Atlassian', '< 7.18.1'),
('CVE-2021-26084', 'Confluence Server', 'Atlassian', '< 7.13.0'),
('CVE-2023-22527', 'Confluence Server', 'Atlassian', '< 8.5.4'),
-- Jira Server (PAYPAL, apple)
('CVE-2019-11581', 'Jira Server', 'Atlassian', '< 8.2.4'),
('CVE-2022-0540', 'Jira Server', 'Atlassian', '< 8.22.0'),
-- GitLab (PAYPAL, apple)
('CVE-2021-22205', 'Gitlab', 'GitLab', '< 13.10.3'),
('CVE-2023-7028', 'Gitlab', 'GitLab', '< 16.7.2'),
('CVE-2024-45409', 'Gitlab', 'GitLab', '< 17.3.3'),
-- Jenkins (PAYPAL, apple)
('CVE-2024-23897', 'Jenkins', 'Jenkins', '< 2.442'),
('CVE-2019-1003000', 'Jenkins', 'Jenkins', '< 2.164'),
-- Oracle (Starbucks)
('CVE-2020-14882', 'Oracle', 'Oracle', '< 14.1.1'),
('CVE-2020-14883', 'Oracle', 'Oracle', '< 14.1.1'),
('CVE-2020-14750', 'Oracle', 'Oracle', '< 14.1.1'),
('CVE-2020-14871', 'Oracle', 'Oracle', '< 11.4.27'),
('CVE-2020-2555', 'Oracle', 'Oracle', '< 12.2.1.4'),
('CVE-2012-3152', 'Oracle', 'Oracle', ''),
('CVE-2015-4852', 'Oracle', 'Oracle', '< 12.2.1'),
-- Java (Uber)
('CVE-2021-44228', 'Java', 'Apache', '< 2.15.0'),
('CVE-2020-6287', 'Java', 'SAP', '< 7.50'),
('CVE-2016-9563', 'Java', 'SAP', '< 7.50'),
('CVE-2010-5326', 'Java', 'SAP', ''),
('CVE-2016-3976', 'Java', 'SAP', '< 7.40'),
-- Apache (Yahoo, VulnWeb Demo)
('CVE-2021-41773', 'Apache', 'Apache', '= 2.4.49'),
('CVE-2021-42013', 'Apache', 'Apache', '= 2.4.50'),
('CVE-2023-25690', 'Apache', 'Apache', '< 2.4.56'),
('CVE-2024-38475', 'Apache', 'Apache', '< 2.4.60'),
-- PHP (VulnWeb Demo)
('CVE-2024-4577', 'PHP', 'PHP', '< 8.3.8'),
('CVE-2023-3824', 'PHP', 'PHP', '< 8.0.30'),
-- MySQL (GitHub, Shopify)
('CVE-2023-21977', 'MySQL', 'Oracle', '< 8.0.33'),
('CVE-2024-21047', 'MySQL', 'Oracle', '< 8.0.37'),
-- IOS XE (PAYPAL, apple)
('CVE-2023-20198', 'Ios Xe', 'Cisco', '< 17.9.4a'),
('CVE-2023-20273', 'Ios Xe', 'Cisco', '< 17.9.4a'),
-- Junos (PAYPAL, apple)
('CVE-2024-21591', 'Junos', 'Juniper', '< 20.4R3-S9'),
('CVE-2023-36845', 'Junos', 'Juniper', '< 20.4R3-S8'),
-- EOS (PAYPAL, apple)
('CVE-2023-24512', 'Eos', 'Arista', '< 4.28.4M');

