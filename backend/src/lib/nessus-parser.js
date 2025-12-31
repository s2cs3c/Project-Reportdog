/**
 * Nessus XML Parser
 * Parses .nessus (XML) files and converts them to PwnDoc vulnerability format
 */

const xml2js = require('xml2js');

/**
 * Parse Nessus XML content and convert to PwnDoc vulnerability format
 * @param {string} xmlContent - Raw XML content from .nessus file
 * @param {string} locale - Target locale for vulnerability details (default: 'en')
 * @returns {Promise<Array>} Array of vulnerabilities in PwnDoc format
 */
async function parseNessusXML(xmlContent, locale = 'en') {
    const parser = new xml2js.Parser({ explicitArray: false, mergeAttrs: true });
    
    try {
        const result = await parser.parseStringPromise(xmlContent);
        const vulnerabilities = [];
        const seenPluginIds = new Set();

        // Handle NessusClientData_v2 format
        const report = result.NessusClientData_v2?.Report;
        if (!report) {
            throw new Error('Invalid Nessus XML format: Missing NessusClientData_v2 or Report element');
        }

        // Get all ReportHosts (can be single object or array)
        let reportHosts = report.ReportHost;
        if (!reportHosts) {
            return vulnerabilities;
        }
        if (!Array.isArray(reportHosts)) {
            reportHosts = [reportHosts];
        }

        for (const host of reportHosts) {
            let reportItems = host.ReportItem;
            if (!reportItems) continue;
            if (!Array.isArray(reportItems)) {
                reportItems = [reportItems];
            }

            for (const item of reportItems) {
                // Skip informational items (severity 0)
                const severity = parseInt(item.severity, 10);
                if (severity === 0) continue;

                // Skip duplicates based on pluginID
                const pluginId = item.pluginID;
                if (seenPluginIds.has(pluginId)) continue;
                seenPluginIds.add(pluginId);

                const vuln = convertReportItemToVulnerability(item, locale);
                if (vuln) {
                    vulnerabilities.push(vuln);
                }
            }
        }

        return vulnerabilities;
    } catch (error) {
        if (error.message.includes('Invalid Nessus XML')) {
            throw error;
        }
        throw new Error(`Failed to parse Nessus XML: ${error.message}`);
    }
}

/**
 * Convert a Nessus ReportItem to PwnDoc vulnerability format
 * @param {Object} item - Nessus ReportItem object
 * @param {string} locale - Target locale
 * @returns {Object} PwnDoc vulnerability object
 */
function convertReportItemToVulnerability(item, locale) {
    const title = item.pluginName || 'Unknown Vulnerability';
    
    // Build description from synopsis and description
    let description = '';
    if (item.synopsis) {
        description += `<p><strong>Synopsis:</strong></p><p>${escapeHtml(item.synopsis)}</p>`;
    }
    if (item.description) {
        description += `<p><strong>Description:</strong></p><p>${escapeHtml(item.description).replace(/\n/g, '<br>')}</p>`;
    }
    if (item.plugin_output) {
        description += `<p><strong>Plugin Output:</strong></p><pre>${escapeHtml(item.plugin_output)}</pre>`;
    }

    // Build observation from plugin output and affected hosts
    let observation = '';
    if (item.port && item.port !== '0') {
        observation = `<p>Affected Port: ${item.port}/${item.protocol || 'tcp'}</p>`;
    }

    // Build remediation from solution
    let remediation = '';
    if (item.solution) {
        remediation = `<p>${escapeHtml(item.solution).replace(/\n/g, '<br>')}</p>`;
    }

    // Build references array
    const references = [];
    
    // Add CVEs
    if (item.cve) {
        const cves = Array.isArray(item.cve) ? item.cve : [item.cve];
        cves.forEach(cve => references.push(`https://nvd.nist.gov/vuln/detail/${cve}`));
    }
    
    // Add see_also links
    if (item.see_also) {
        // Handle both array (multiple elements) and string (single element with newlines)
        const seeAlsoItems = Array.isArray(item.see_also) ? item.see_also : [item.see_also];
        seeAlsoItems.forEach(seeAlso => {
            // Each item might contain multiple URLs separated by newlines
            const links = seeAlso.split('\n').filter(link => link.trim());
            references.push(...links);
        });
    }

    // Add plugin reference
    if (item.pluginID) {
        references.push(`https://www.tenable.com/plugins/nessus/${item.pluginID}`);
    }

    // Map severity to priority
    // Nessus severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
    // PwnDoc priority: 1=Low, 2=Medium, 3=High, 4=Urgent
    const severityToPriority = {
        1: 1, // Low -> Low
        2: 2, // Medium -> Medium
        3: 3, // High -> High
        4: 4  // Critical -> Urgent
    };
    const priority = severityToPriority[parseInt(item.severity, 10)] || null;

    // Get CVSS v3 vector if available
    let cvssv3 = null;
    if (item.cvss3_vector) {
        cvssv3 = item.cvss3_vector;
    } else if (item.cvss3_base_score) {
        // If only score is available, we can't construct a full vector
        cvssv3 = null;
    }

    // Determine vulnerability type based on plugin family
    let vulnType = null;
    if (item.pluginFamily) {
        vulnType = item.pluginFamily;
    }

    // Determine category based on risk factor or plugin family
    let category = null;
    if (item.pluginFamily) {
        category = mapPluginFamilyToCategory(item.pluginFamily);
    }

    // Map remediation complexity based on solution complexity
    // This is a rough estimation
    let remediationComplexity = null;
    if (item.solution) {
        const solutionLower = item.solution.toLowerCase();
        if (solutionLower.includes('upgrade') || solutionLower.includes('update') || solutionLower.includes('patch')) {
            remediationComplexity = 1; // Easy - just update
        } else if (solutionLower.includes('configure') || solutionLower.includes('disable')) {
            remediationComplexity = 2; // Medium - configuration change
        } else if (solutionLower.includes('redesign') || solutionLower.includes('replace')) {
            remediationComplexity = 3; // Complex - major change
        }
    }

    return {
        cvssv3: cvssv3,
        cvssv4: null,
        priority: priority,
        remediationComplexity: remediationComplexity,
        category: category,
        details: [{
            locale: locale,
            title: title,
            vulnType: vulnType,
            description: description,
            observation: observation,
            remediation: remediation,
            references: references,
            customFields: []
        }]
    };
}

/**
 * Map Nessus plugin family to PwnDoc category
 * @param {string} pluginFamily - Nessus plugin family
 * @returns {string|null} PwnDoc category or null
 */
function mapPluginFamilyToCategory(pluginFamily) {
    const categoryMap = {
        'Web Servers': 'Web Application',
        'CGI abuses': 'Web Application',
        'CGI abuses : XSS': 'Web Application',
        'Databases': 'Database',
        'DNS': 'Network',
        'FTP': 'Network',
        'Firewalls': 'Network',
        'Gain a shell remotely': 'Remote Code Execution',
        'General': null,
        'Misc.': null,
        'Netware': 'Network',
        'Peer-To-Peer File Sharing': 'Network',
        'Policy Compliance': 'Compliance',
        'Port scanners': null,
        'RPC': 'Network',
        'SCADA': 'Industrial Control Systems',
        'SMTP problems': 'Network',
        'SNMP': 'Network',
        'Service detection': null,
        'Settings': null,
        'Slackware Local Security Checks': 'Operating System',
        'Ubuntu Local Security Checks': 'Operating System',
        'Red Hat Local Security Checks': 'Operating System',
        'CentOS Local Security Checks': 'Operating System',
        'Debian Local Security Checks': 'Operating System',
        'Fedora Local Security Checks': 'Operating System',
        'Windows': 'Operating System',
        'Windows : Microsoft Bulletins': 'Operating System',
        'Windows : User management': 'Operating System',
        'MacOS X Local Security Checks': 'Operating System',
        'Backdoors': 'Malware',
        'Brute force attacks': 'Authentication',
        'Default Unix Accounts': 'Authentication',
        'Denial of Service': 'Denial of Service',
        'Gentoo Local Security Checks': 'Operating System',
        'HP-UX Local Security Checks': 'Operating System',
        'Mandriva Local Security Checks': 'Operating System',
        'Mobile Devices': 'Mobile',
        'Solaris Local Security Checks': 'Operating System',
        'SuSE Local Security Checks': 'Operating System',
        'VMware ESX Local Security Checks': 'Virtualization',
        'Virtuozzo Local Security Checks': 'Virtualization'
    };

    return categoryMap[pluginFamily] || null;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Get summary statistics from parsed vulnerabilities
 * @param {Array} vulnerabilities - Array of parsed vulnerabilities
 * @returns {Object} Summary statistics
 */
function getSummary(vulnerabilities) {
    const summary = {
        total: vulnerabilities.length,
        byPriority: {
            urgent: 0,
            high: 0,
            medium: 0,
            low: 0
        },
        byCategory: {}
    };

    for (const vuln of vulnerabilities) {
        // Count by priority
        switch (vuln.priority) {
            case 4: summary.byPriority.urgent++; break;
            case 3: summary.byPriority.high++; break;
            case 2: summary.byPriority.medium++; break;
            case 1: summary.byPriority.low++; break;
        }

        // Count by category
        const category = vuln.category || 'Uncategorized';
        summary.byCategory[category] = (summary.byCategory[category] || 0) + 1;
    }

    return summary;
}

module.exports = {
    parseNessusXML,
    convertReportItemToVulnerability,
    getSummary
};

