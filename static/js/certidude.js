"use strict";
import * as asn1js from "asn1js";
import {
  arrayBufferToString,
  stringToArrayBuffer,
  toBase64,
  bufferToHexCodes
} from "pvutils";
import {
  getCrypto,
  getAlgorithmParameters,
} from "../node_modules/pkijs/src/common.js";
import CertificationRequest from "../node_modules/pkijs/src/CertificationRequest.js";
import AttributeTypeAndValue from "../node_modules/pkijs/src/AttributeTypeAndValue.js";
import { pkcs12chain } from "./pkcs12chain.js";
import {
  pkijsToPem,
  pkijsToBase64,
  pemToBase64,
} from "./util.js"

const DEVICE_KEYWORDS = ["Android", "iPhone", "iPad", "Windows", "Ubuntu", "Fedora", "Mac", "Linux"];

jQuery.timeago.settings.allowFuture = true;

window.cryptoEngine = getCrypto();
if (typeof window.cryptoEngine === "undefined")
  console.error("No WebCrypto extension found");

function onLaunchShell(common_name) {
    $.post({
      url: "/api/signed/" + common_name + "/shell/",
      error: function() {
        alert("Failed to launch shell for: " + common_name);
      },
      success: function(blob) {
        console.info(blob);
        if (blob.action == "start-session") {
          console.info("Returned shell blob:", blob);
          var win = window.open("/shell.html#" + blob.source + "/" + blob.target, '_blank');
          if (win) {
            win.focus();
          } else {
            alert("Please disable popup blocker for this site!");
          }
	} else {
          alert("Failed to start session");
        }
      }
    });
    return false;
}

function onRejectRequest(e, id, sha256sum) {
  $(this).button('loading');
  $.ajax({
    url: "/api/request/id/" + id + "/?sha256sum=" + sha256sum,
    type: "delete"
  });
}

function onSignRequest(e, id, sha256sum) {
  e.preventDefault();
  $(e.target).button('loading');
  $.ajax({
    url: "/api/request/id/" + id + "/?sha256sum=" + sha256sum,
    type: "post"
  });
  return false;
}

function normalizeCommonName(j) {
    return j.replace("@", "--").split(".").join("-"); // dafuq ?!
}

function onShowAll() {
  var options = document.querySelectorAll(".option");
  for (i = 0; i < options.length; i++) {
      options[i].style.display = "block";
  }
}

function onKeyGen() {
  return new Promise(async (resolve, reject) => {
    if (window.navigator.userAgent.indexOf(" Edge/") >= 0) {
      $("#enroll .loader-container").hide();
      $("#enroll .edge-broken").show();
      return;
    }

    let pkcs10 = new CertificationRequest();

    // Commonname
    pkcs10.subject.typesAndValues.push(
      new AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new asn1js.Utf8String({ value: common_name }),
      })
    );

    pkcs10.attributes = [];

    let algorithm;
    if (authority.certificate.algorithm == "rsa") {
      algorithm = getAlgorithmParameters(
        window.authority.certificate.signature_algorithm, "generatekey");
    }
    if (authority.certificate.algorithm == "ec") {
      if(authority.certificate.curve.startsWith("secp")) {
        algorithm = getAlgorithmParameters(
          "ECDSA", "generatekey");
        algorithm.algorithm.namedCurve = 
          `P-${authority.certificate.curve.slice(4,7)}`;
      }
    }
    if ("hash" in algorithm.algorithm)
      algorithm.algorithm.hash.name = window.authority.certificate.hash_algorithm;

    const keyPair = await window.cryptoEngine.generateKey(
      algorithm.algorithm, true, algorithm.usages);
    window.keys = keyPair;
    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.privateKey;

    await pkcs10.subjectPublicKeyInfo.importKey(publicKey);
    await pkcs10.sign(privateKey, window.authority.certificate.hash_algorithm);
    window.csr = pkcs10;
    console.info("Certification request created");

    $("#enroll .loader-container").hide();
    var prefix = null;
    for (i in DEVICE_KEYWORDS) {
    var keyword = DEVICE_KEYWORDS[i];
      if (window.navigator.userAgent.indexOf(keyword) >= 0) {
        prefix = keyword.toLowerCase();
        break;
      }
    }

    if (prefix == null) {
      $(".option").show();
      return;
    }

    var protocols = query.protocols.split(",");
    console.info("Showing snippets for:", protocols);
    for (var j = 0; j < protocols.length; j++) {
      var options = document.querySelectorAll(
        ".option." + protocols[j] + "." + prefix
      );
      for (i = 0; i < options.length; i++) {
        options[i].style.display = "block";
      }
    }
    $(".option.any").show();

    resolve();
  });
}

function blobToUuid(blob) {
  return new Promise((resolve, reject) => {
    window.cryptoEngine.digest(
    { name: "SHA-1" },
    stringToArrayBuffer(blob))
    .then((res) => {
      res = bufferToHexCodes(res).toLowerCase();
      res =
        res.substring(0, 8) +
        "-" +
        res.substring(8, 12) +
        "-" +
        res.substring(12, 16) +
        "-" +
        res.substring(16, 20) +
        "-" +
        res.substring(20);

      resolve(res);
    });
  });
}

function onEnroll(encoding) {
  console.info("Service name:", query.title);

  console.info("User agent:", window.navigator.userAgent);
  var xhr = new XMLHttpRequest();
  xhr.open('GET', "/api/certificate/");
  xhr.onload = async function() {
    if (xhr.status === 200) {
      const caBase64 = pemToBase64(xhr.responseText);

      var xhr2 = new XMLHttpRequest();
      xhr2.open("PUT", "/api/token/?token=" + query.token );
      xhr2.onload = async function() {
        if (xhr2.status === 200) {
          var a = document.createElement("a");
          const certBase64 = pemToBase64(xhr.responseText);

          // Private key to base64 (for pkcs12chain)
          let privKeyBase64 = await pkijsToBase64(keys.privateKey);

          switch(encoding) {
            case 'p12':
              var p12 = await pkcs12chain(privKeyBase64, [certBase64, caBase64], "", window.authority.certificate.hash_algorithm);

              var buf = arrayBufferToString(p12.toSchema().toBER(false));
              var mimetype = "application/x-pkcs12"
              a.download = query.title + ".p12";
              break
            case 'sswan':
              var p12 = arrayBufferToString(
                  (await pkcs12chain(privKeyBase64, [certBase64, caBase64], "", window.authority.certificate.hash_algorithm)).toSchema().toBER(false));
                
              var buf = JSON.stringify({
                  uuid: await blobToUuid(authority.namespace),
                  name: authority.namespace,
                  type: "ikev2-cert",
                  'ike-proposal': window.authority.strongswan.ike,
                  'esp-proposal': window.authority.strongswan.esp,
                  remote: {
                      addr: authority.namespace,
                      revocation: {
                          crl: false,
                          strict: true
                      }
                  },
                  local: {
                      p12: toBase64(p12),
                  }
              });
              console.info("Buf is:", buf);
              var mimetype = "application/vnd.strongswan.profile"
              a.download = query.title + ".sswan";
              break
            case 'ovpn':
              let privKeyPem = await pkijsToPem(keys.privateKey);

              var buf = nunjucks.render('snippets/openvpn-client.conf', {
                  authority: authority,
                  key: privKeyPem,
                  cert: xhr2.responseText,
                  ca: xhr.responseText
              });
              var mimetype = "application/x-openvpn-profile";
              a.download = query.title + ".ovpn";
              break
            case 'mobileconfig':
              var p12 = arrayBufferToString(
                (await pkcs12chain(
                  privKeyBase64, [certBase64, caBase64],
                  "1234", window.authority.certificate.hash_algorithm))
                .toSchema().toBER(false));

              var buf = nunjucks.render('snippets/ios.mobileconfig', {
                  authority: authority,
                  service_uuid: await blobToUuid(query.title),
                  conf_uuid: await blobToUuid(query.title + " conf1"),
                  title: query.title,
                  common_name: common_name,
                  gateway: authority.namespace,
                  p12_uuid: await blobToUuid(p12),
                p12: toBase64(p12),
                ca_uuid: await blobToUuid(caBase64),
                ca: caBase64,
              });
              var mimetype = "application/x-apple-aspen-config";
              a.download = query.title + ".mobileconfig";
              break
          }
          a.href = "data:" + mimetype + ";base64," + toBase64(buf);
          console.info("Offering bundle for download");
          document.body.appendChild(a); // Firefox needs this!
          a.click();
        } else {
          if (xhr2.status == 403) { alert("Token used or expired"); }
          console.info('Request failed.  Returned status of ' + xhr2.status);
          try {
            var r = JSON.parse(xhr2.responseText);
            console.info("Server said: " + r.title);
            console.info(r.description);
          } catch(e) {
             console.info("Server said: " + xhr2.statusText);
          }
        }
      };
      xhr2.send(await pkijsToPem(window.csr));
    }
  }
  xhr.send();
}

async function onHashChanged() {

    window.query = {};
    var a = location.hash.substring(1).split('&');
    for (var i = 0; i < a.length; i++) {
        var b = a[i].split('=');
        query[decodeURIComponent(b[0])] = decodeURIComponent(b[1] || '');
    }

    console.info("Hash is now:", query);

    $.get({
        method: "GET",
        url: "/api/bootstrap/",
        error: function(response) {
            if (response.responseJSON) {
                var msg = response.responseJSON
            } else {
                var msg = { title: "Error " + response.status, description: response.statusText }
            }
            $("#view-dashboard").html(env.render('views/error.html', { message: msg }));
        },
        success: async function(authority) {
          window.authority = authority

          var prefix = "unknown";
          for (i in DEVICE_KEYWORDS) {
            var keyword = DEVICE_KEYWORDS[i];
            if (window.navigator.userAgent.indexOf(keyword) >= 0) {
              prefix = keyword.toLowerCase();
              break;
            }
          }

          if (window.location.protocol != "https:") {
              $("#view-dashboard").html(env.render('views/insecure.html', {authority:authority}));
          } else {
              // Device identifier
              var dig = await blobToUuid(window.navigator.userAgent);
              window.common_name = prefix + "-" + dig.substring(0, 5);
              console.info("Device identifier:", common_name);
              
              if (query.action == "enroll") {
                  $("#view-dashboard").html(env.render('views/enroll.html', {
                    common_name: common_name,
                    authority: authority,
                    token: query.token,
                  }));
                  var options = document.querySelectorAll(".option");
                  for (i = 0; i < options.length; i++) {
                      options[i].style.display = "none";
                  }
                  console.info("Generating key pair...");
                  await onKeyGen();
              } else {
                  loadAuthority(query);
              }
          }
        }
    });

}

function onToggleAccessButtonClicked(e) {
    e.preventDefault();
    var cn = $(e.target).attr("data-cn");
    var id = $(e.target).attr("data-id");

    var value = $(e.target).attr("data-value") == 'True';

    var textValues = {false:"Disable",true:"Enable"}

    var confirm = window.confirm("Do you want to " + textValues[value] +" "+ cn);

    if (confirm) {
        $.ajax({
            method: "POST",
            url: "/api/toggleaccess/id/" + id + "/?disable=" + !value
        });
    }
}


function onTagClicked(e) {
    e.preventDefault();
    var cn = $(e.target).attr("data-cn");
    var cert_id = $(e.target).attr("data-id");
    var id = $(e.target).attr("title");
    var value = $(e.target).html();
    var updated = prompt("Enter new tag or clear to remove the tag", value);
    if (updated == "") {
        $(event.target).addClass("disabled");
        $.ajax({
            method: "DELETE",
            url: "/api/signed/id/" + cert_id + "/tag/" + id + "/"
        });
    } else if (updated && updated != value) {
        $(e.target).addClass("disabled");
        $.ajax({
            method: "PUT",
            url: "/api/signed/id/" + cert_id + "/tag/" + id + "/",
            data: { value: updated },
            dataType: "text",
            complete: function(xhr, status) {
                console.info("Tag added successfully", xhr.status,  status);
            },
            success: function() {
            },
            error: function(xhr, status, e) {
                console.info("Submitting request failed with:", status, e);
                alert(e);
            }
        });
    }
    return false;
}

function onNewTagClicked(e) {
    e.preventDefault();
    var cn = $(e.target).attr("data-cn");
    var key = $(e.target).attr("data-key");
    var value = prompt("Enter new " + key + " tag for " + cn);
    var id = $(e.target).attr("data-id");
    if (!value) return;
    if (value.length == 0) return;
    var $container = $(".tags[data-id='" + id + "']");
    $container.addClass("disabled");
    $.ajax({
        method: "POST",
        url: "/api/signed/id/" + id + "/tag/",
        data: { value: value, key: key },
        dataType: "text",
        complete: function(xhr, status) {
            console.info("Tag added successfully", xhr.status,  status);
        },
        success: function() {
            $container.removeClass("disabled");
        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    });
    return false;
}

function onTagFilterChanged() {
    var key = $(event.target).val();
    console.info("New key is:", key);
}

function onLogEntry (e) {
    if (e.data) {
        e = JSON.parse(e.data);
        e.fresh = true;
    }

    if ($("#log-level-" + e.severity).prop("checked")) {
        $("#log-entries").prepend(env.render("views/logentry.html", {
            entry: {
                created: new Date(e.created).toLocaleString(),
                message: e.message,
                severity: e.severity,
                fresh: e.fresh,
                keywords: e.message.toLowerCase().split(/,?[ <>/]+/).join("|")
            }
        }));
    }
};

function onRequestSubmitted(e) {
    console.log("Request submitted:", e.data);
    $.ajax({
        method: "GET",
        url: "/api/request/id/" + e.data + "/",
        dataType: "json",
        success: function(request, status, xhr) {
            console.info("Going to prepend:", request);
            onRequestDeleted(request.id); // Delete any existing ones just in case
            $("#pending_requests").prepend(
                env.render('views/request.html', { request: request, authority: authority }));
            $("#pending_requests time").timeago();
        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onRequestDeleted(e) {
    console.log("Removing deleted request", e.data);
    $("#request-" + e.data).remove();
}

function onLeaseUpdate(e) {
    var slug = normalizeCommonName(e.data);
    console.log("Lease updated:", e.data);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + e.data + "/lease/",
        dataType: "json",
        success: function(lease, status, xhr) {
            console.info("Retrieved lease update details:", lease);
            lease.age = (new Date() - new Date(lease.last_seen)) / 1000.0
            var $lease = $("#certificate-" + slug + " .lease");
            $lease.html(env.render('views/lease.html', {
                certificate: {
                    lease: lease }}));
            $("time", $lease).timeago();
            filterSigned();
        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onRequestSigned(e) {
    console.log("Request signed:", e.data);
    var id = e.data
    //var slug = normalizeCommonName(e.data);
    //console.log("Removing:", slug);
    console.log("Removing:", e.data);

    $("#request-" + id).slideUp("normal", function() { $(this).remove(); });
    $("#certificate-" + id).slideUp("normal", function() { $(this).remove(); });

    $.ajax({
        method: "GET",
        url: "/api/signed/id/" + e.data + "/",
        dataType: "json",
        success: function(certificate, status, xhr) {
            console.info("Retrieved certificate:", certificate);
            $("#signed_certificates").prepend(
                env.render('views/signed.html', { certificate: certificate, session: session }));
            $("#signed_certificates time").timeago(); // TODO: optimize?
            filterSigned();
        },
        error: function(response) {
            console.info("Failed to retrieve certificate:", response);
        }
    });
}

function onCertificateRevoked(e) {
    console.log("Removing revoked certificate", e.data);
    $("#certificate-" + e.data).slideUp("normal", function() { $(this).remove(); });
}

function onTagUpdated(e) {
    var id = e.data;

    console.log("Tag updated event recevied", id);
    $.ajax({
        method: "GET",
        url: "/api/signed/id/" + id + "/tag/",
        dataType: "json",
        success:function(tags, status, xhr) {
            console.info("Updated", id, "tags", tags);
            $(".tags[data-id='" + id+"']").html(
                env.render('views/tags.html', {
                    certificate: {
                        id:id,
                        tags:tags }}));
        }
    })
}

function onAttributeUpdated(e) {
    var cn = e.data;
    console.log("Attributes updated", cn);
    $.ajax({
        method: "GET",
        url: "/api/signed/" + cn + "/attr/",
        dataType: "json",
        success:function(attributes, status, xhr) {
            console.info("Updated", cn, "attributes", attributes);
            $(".attributes[data-cn='" + cn + "']").html(
                env.render('views/attributes.html', {
                    certificate: {
                        common_name: cn,
                        attributes:attributes }}));
        }
    })
}

function onSubmitRequest() {
    $.ajax({
        method: "POST",
        url: "/api/request/",
        headers: {
            "Accept": "application/json; charset=utf-8",
            "Content-Type": "application/pkcs10"
        },
        data: $("#request_body").val(),

        success:function(attributes, status, xhr) {
            // Close the modal
            $("[data-dismiss=modal]").trigger({ type: "click" });
        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    })
}

function onServerStarted() {
    console.info("Server started");
    location.reload();
}

function onServerStopped() {
    $("#view-dashboard").html('<div class="loader"></div><p>Server under maintenance</p>');
    console.info("Server stopped");

}

function onIssueToken() {
    $.ajax({
        method: "POST",
        url: "/api/token/",
        data: { username: $("#token_username").val(), mail: $("#token_mail").val() },
        dataType: "text",
        complete: function(xhr, status) {
            console.info("Token sent successfully", xhr.status, status);
        },
        success: function(data) {
            var url = JSON.parse(data).url;
            console.info("DATA:", url);
            var code = new QRCode({
                content: url,
                width: 512,
                height: 512,
            });
            document.getElementById("token_qrcode").innerHTML = code.svg();

        },
        error: function(xhr, status, e) {
            console.info("Submitting request failed with:", status, e);
            alert(e);
        }
    });
}

function onInstanceAvailabilityUpdated(e) {

    var id = e.data;

    $.ajax({
        method: "GET",
        dataType: "text",
        url: "/api/toggleaccess/id/"+id,
        success: function(data) {

            var value = data == 'True'

            if(value) {
                $("#availability-"+id).html("Enable");
                $("#availability-"+id).attr("data-value","True");
            } else {
                $("#availability-"+id).html("Disable");
                $("#availability-"+id).attr("data-value","False");
            }
        }
    });
}

function filterSigned() {
    if ($("#search").val() != "") {
        console.info("Not filtering by state since keyword filter is active");
        return;
    }

    $("#signed_certificates .filterable").each(function(i,j) {
        var last_seen = j.getAttribute("data-last-seen");
        var state = "new";
        if (last_seen) {
            var age = (new Date() - new Date(last_seen)) / 1000;
            if (age > 172800) {
                state = "dead";
            } else if (age > 10800) {
                state = "offline";
            } else {
                state = "online";
            }
        }
        j.setAttribute("data-state", state);
        j.style.display = $("#signed-filter-" + state).prop("checked") ? "block" : "none";
    });
        $("#signed-total").html($("#signed_certificates .filterable").length);
        $("#signed-filter-counter").html($("#signed_certificates .filterable:visible").length);
}

function loadAuthority(query) {
    console.info("Loading CA, to debug: curl " + window.location.href + " --negotiate -u : -H 'Accept: application/json'");
    $.ajax({
        method: "GET",
        url: "/api/session/",
        dataType: "json",
        error: function(response) {
            if (response.responseJSON) {
                var msg = response.responseJSON
            } else {
                var msg = { title: "Error " + response.status, description: response.statusText }
            }
            $("#view-dashboard").html(env.render('views/error.html', { message: msg }));
        },
        success: function(session, status, xhr) {
            window.session = session;

            console.info("Loaded:", session);
            $("#login").hide();
            $("#search").show();

            /**
             * Render authority views
             **/
            $("#view-dashboard").html(env.render('views/authority.html', {
                session: session,
                authority: authority,
                window: window,

                // Parameters for unified snippets
                dhparam_path: "/etc/ssl/dhparam.pem",
                key_path: "/etc/certidude/authority/" + window.authority.namespace + "/host_key.pem",
                certificate_path: "/etc/certidude/authority/" + window.authority.namespace + "/host_cert.pem",
                authority_path: "/etc/certidude/authority/" + window.authority.namespace + "/ca_cert.pem",
                revocations_path: "/etc/certidude/authority/" + window.authority.namespace + "/crl.pem",
                common_name: "$NAME"
            }));

            // Initial filtering
            $("#signed-filter .btn").on('change', filterSigned);
            filterSigned();

            // Attach timeago events
            $("time").timeago();

            if (window.authority) {
                $("#log input").each(function(i, e) {
                    console.info("e.checked:", e.checked , "and", e.id, "@localstorage is", localStorage[e.id], "setting to:", localStorage[e.id] || e.checked, "bool:", localStorage[e.id] || e.checked == "true");
                    e.checked = localStorage[e.id] ? localStorage[e.id] == "true" : e.checked;
                });

                $("#log input").change(function() {
                    localStorage[this.id] = this.checked;
                });

                console.info("Opening EventSource from:", window.session.events);

                window.source = new EventSource(window.session.events);

                source.onmessage = function(event) {
                    console.log("Received server-sent event:", event);
                }


                source.addEventListener("lease-update", onLeaseUpdate);
                source.addEventListener("request-deleted", onRequestDeleted);
                source.addEventListener("request-submitted", onRequestSubmitted);
                source.addEventListener("request-signed", onRequestSigned);
                source.addEventListener("certificate-revoked", onCertificateRevoked);
                source.addEventListener("tag-update", onTagUpdated);
                source.addEventListener("attribute-update", onAttributeUpdated);
                source.addEventListener("server-started", onServerStarted);
                source.addEventListener("server-stopped", onServerStopped);
                source.addEventListener("instance-access-update", onInstanceAvailabilityUpdated);

            }

            $("nav#menu li").click(function(e) {
                $("section").hide();
                $("section#" + $(e.target).attr("data-section")).show();
            });



            $("#enroll").click(async function() {
                var keys = await window.cryptoEngine.generateKey(
                {
                  name: window.authority.certificate.key_type_specific,
                  modulusLength: window.authority.certificate.key_size,
                  publicExponent: new Uint8Array([1, 0, 1]),
                  hash: window.authority.certificate.hash_algorithm,
                },
                true,
                ["encrypt", "decrypt"]);

                $.ajax({
                    method: "POST",
                    url: "/api/token/",
                    data: "username=" + session.user.name,
                    complete: function(xhr, status) {
                        console.info("Token generated successfully:", xhr, status);

                    },
                    error: function(xhr, status, e) {
                        console.info("Token generation failed:", status, e);
                        alert(e);
                    }
                });



                var privateKeyBuffer = pkijsToPem(keys.privateKey);
            });

            /**
             * Set up search bar
              */
            $(window).on("search", function() {
                var q = $("#search").val();
                $(".filterable").each(function(i, e) {
                    if ($(e).attr("data-keywords").toLowerCase().indexOf(q) >= 0) {
                        $(e).show();
                    } else {
                        $(e).hide();
                    }
                });
                if (q.length == 0) {
                    filterSigned();
                    $("#signed-filter .btn").removeClass("disabled").prop("disabled", false);
                } else {
                    $("#signed-filter .btn").addClass("disabled").prop("disabled", true);
                }
            });




            /**
             * Bind key up event of search bar
             */
            $("#search").on("keyup", function() {
                if (window.searchTimeout) { clearTimeout(window.searchTimeout); }
                window.searchTimeout = setTimeout(function() { $(window).trigger("search"); }, 500);
            });

            if (session.request_submission_allowed) {
                $("#request_submit").click(function() {
                    $(this).addClass("busy");
                    $.ajax({
                        method: "POST",
                        contentType: "application/pkcs10",
                        url: "/api/request/",
                        data: $("#request_body").val(),
                        dataType: "text",
                        complete: function(xhr, status) {
                            console.info("Request submitted successfully, server returned", xhr.status,  status);
                            $("#request_submit").removeClass("busy");
                        },
                        success: function() {
                            // Clear textarea on success
                            $("#request_body").val("");
                        },
                        error: function(xhr, status, e) {
                            console.info("Submitting request failed with:", status, e);
                            alert(e);
                        }
                    });
                });
            }

            $("nav .nav-link.dashboard").removeClass("disabled").click(function() {
                $("#column-requests").show();
                $("#column-signed").show();
                $("#column-revoked").show();
                $("#column-log").hide();
            });

            /**
             * Fetch log entries
             */
            if (session.features.logging) {
                if ($("#column-log:visible").length) {
                    loadLog();
                }
                $("nav .nav-link.log").removeClass("disabled").click(function() {
                    loadLog();
                    $("#column-requests").show();
                    $("#column-signed").show();
                    $("#column-revoked").show();
                    $("#column-log").hide();
                });
            } else {
                console.info("Log disabled");
            }
        }
    });
}

function loadLog() {
    if (window.log_initialized) {
        console.info("Log already loaded");
        return;
    }
    console.info("Loading log...");
    window.log_initialized = true;
    $.ajax({
        method: "GET",
        url: "/api/log/?limit=100",
        dataType: "json",
        success: function(entries, status, xhr) {
            console.info("Got", entries.length, "log entries");
            for (var j = entries.length-1; j--; ) {
                onLogEntry(entries[j]);
            };
            source.addEventListener("log-entry", onLogEntry);
            $("#column-log .loader-container").hide();
            $("#column-log .content").show();
        }
    });
}

function datetimeFilter(s) {
    return new Date(s);
}

function serialFilter(s) {
    return s.substring(0,s.length-14) + " " +
        s.substring(s.length-14);
}

$(document).ready(function() {
    window.env = new nunjucks.Environment();
    env.addFilter("datetime", datetimeFilter);
    env.addFilter("serial", serialFilter);
    onHashChanged();
});

window.onLaunchShell = onLaunchShell;
window.onRejectRequest = onRejectRequest;
window.onSignRequest = onSignRequest;
window.onShowAll = onShowAll;
window.onKeyGen = onKeyGen;
window.onEnroll = onEnroll;
window.onHashChanged = onHashChanged;
window.onToggleAccessButtonClicked = onToggleAccessButtonClicked;
window.onTagClicked = onTagClicked;
window.onNewTagClicked = onNewTagClicked;
window.onTagFilterChanged = onTagFilterChanged;
window.onLogEntry = onLogEntry;
window.onRequestSubmitted = onRequestSubmitted;
window.onRequestDeleted = onRequestDeleted;
window.onLeaseUpdate = onLeaseUpdate;
window.onRequestSigned = onRequestSigned;
window.onCertificateRevoked = onCertificateRevoked;
window.onTagUpdated = onTagUpdated;
window.onAttributeUpdated = onAttributeUpdated;
window.onSubmitRequest = onSubmitRequest;
window.onServerStarted = onServerStarted;
window.onServerStopped = onServerStopped;
window.onIssueToken = onIssueToken;
window.onInstanceAvailabilityUpdated = onInstanceAvailabilityUpdated;
