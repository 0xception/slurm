/* Configuration File */

// Comment out for production use.
#define DEBUG true

#ifndef CONFIG_H
#define CONFIG_H

namespace config {

// Service URI as configured in squid ecap adapter. Does not need to actually
// exist as a domain so long as it runs on the same box.
const std::string service_uri =
    "ecap://slurm.domain.com/ecap/services/slurm";

// Injection URL fragments.
// Protocol: Either http or https
// Hostname: Domain name of the public location
// Path: Location of the script to inject
// Script: File name of the script.
#ifdef DEBUG // Development Settings
    const std::string proto = "http"; // could also be "https"
    const std::string hostname = "slurm-dev.domain.com";
    const std::string path = "/";
    const std::string script = "slurm.js";
#else // Production Settings
    const std::string proto = "http"; // could also be "https"
    const std::string hostname = "slurm.domain.com";
    const std::string path = "/";
    const std::string script = "slurm.js";
#endif

// List of domain to be ignored from injection. This will match on any
// subdomain as well. However it does not prevewnt ads from iframed or content
// from other domains that are pulled in. This should be kept short and for
// proper whitelisting we should use squid to prevent the traffic to from
// going to the ecap adapter.
const std::string whitelist[] = {
#ifdef DEBUG // Development Settings
        "purple.com", // Special Development Whitelist
        "slurm-dev.domain.com", // Special Development Whitelist
#endif
        "slurm.domain.com",
};

// List of extensions we should ignore. We also check Content-type for
// text/html however this is just quicker. Feel free to include more extensions
// that you would like to ignore.
const std::string extensions[] = {".js", ".gif", ".jpg", ".png",
                                  ".css", ".zip", ".exe", ".avi",
                                  ".mpg", ".wmv", " wma", ".mp3",
                                  ".aac", ".xml",".jpeg", ".mpeg"};

// Location of log file (must have user.group read/write permissions).
const char *log = "/var/log/squid/slurm.log";

} // End config namespace
#endif
