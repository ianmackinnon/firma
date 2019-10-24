/*global window, $, _ */

var firma = (function () {
  "use strict";

  var app;

  app = {

    /* XHR */

    _xhr: {},
    _xhrDebug: false,
    _xhrBuffers: {},

    ajax: function (name, options) {
      if (app._xhr[name]) {
        if (app._xhrDebug) {
          console.warn("Aborting", name, app._xhr[name]);
        }
        app._xhr[name].abort();
      }

      var abortCallback = options.abort;
      var errorCallback = options.error;
      var successCallback = options.success;
      var completeCallback = options.complete;

      options.success = function (response, textStatus, request) {
        app.parseApi(response);
        if (_.isFunction(successCallback)) {
          successCallback(response, textStatus, request);
        }
      };

      options.error = function (jqXHR, status, error) {
        if (status === "abort") {
          if (_.isFunction(abortCallback)) {
            abortCallback(jqXHR, status, error);
          }
          return;
        }
        app.ajaxBufferClear(name);
        if (_.isFunction(errorCallback)) {
          errorCallback(jqXHR, status, error);
        } else {
          console.error("error", jqXHR, status, error);
        }
      };

      options.complete = function (jqXHR, status) {
        if (app._xhrDebug) {
          console.warn("Complete", name, status, app._xhr[name]);
        }
        delete app._xhr[name];
        if (_.isFunction(completeCallback)) {
          completeCallback(jqXHR, status);
        }
      };

      app._xhr[name] = $.ajax(options);
      if (app._xhrDebug) {
        console.warn("Calling", name, app._xhr[name]);
      }

      return app._xhr[name];
    },

    ajaxBuffer: function (name, options) {
      if (app._xhrDebug) {
        console.log("ajaxBuffer", name, _.cloneDeep(options));
      }
      var complete = options.bufferComplete;
      var waiting = options.bufferWaiting;
      var sendNull = (
        _.isUndefined(options.sendNull) ? true : options.sendNull
      );
      var success = options.success;
      var delay = options.delay;
      var init = options.init;
      delete options.bufferComplete;
      delete options.bufferWaiting;
      delete options.sendNull;
      delete options.delay;
      delete options.init;

      var buffer = app._xhrBuffers[name];
      if (_.isUndefined(buffer) || init) {
        buffer = {
          timeout: null,
          ajax: null,
          timeoutData: undefined,  // Input data for last timeout
          ajaxData: undefined,     // Input data for last ajax request
          resultData: undefined    // Input data for currently displayed output
        };
        app._xhrBuffers[name] = buffer;
      }

      var clear = function () {
        if (buffer.timeout) {
          clearTimeout(buffer.timeout);
          buffer.timeout = null;
          buffer.timeoutData = undefined;
        }
      };

      var abort = function () {
        if (buffer.ajax && buffer.ajax.abort) {
          buffer.ajax.abort();
        }
        buffer.ajax = null;
        buffer.ajaxData = undefined;
      };

      var query;
      var delayQuery = function (data, context) {
        data = _.clone(data);

        if (_.isEqual(data, buffer.resultData)) {
          clear();
          if (_.isFunction(complete)) {
            complete();
          }
          if (app._xhrDebug) {
            console.log("ajaxBuffer: equal result");
          }
          return;
        }

        if (buffer.ajax && _.isEqual(data, buffer.ajaxData)) {
          clear();
          if (app._xhrDebug) {
            console.log("ajaxBuffer: equal ajax");
          }
          return;
        }

        if (buffer.timeout && _.isEqual(data, buffer.timeoutData)) {
          if (app._xhrDebug) {
            console.log("ajaxBuffer: equal timeout");
          }
          return;
        }

        options.success = function (response, textStatus, request) {
          buffer.ajax = null;
          buffer.ajaxData = null;
          buffer.resultData = data;

          if (_.isFunction(success)) {
            success(response, textStatus, request, _.extend(context, {
              data: data
            }));
          }
          if (_.isFunction(complete)) {
            complete();
          }
        };

        query = function (data) {
          if (_.isFunction(waiting)) {
            waiting(_.clone(data));
          }
          app.ajax(name, _.extend(options, {
            data: data
          }));
        };

        clear();
        buffer.timeoutData = data;
        buffer.timeout = setTimeout(function () {
          buffer.ajax = true;
          buffer.ajaxData = data;
          buffer.timeout = null;
          buffer.timeoutData = null;
          if (!sendNull && _.isNull(data)) {
            options.success();
          } else if (_.isFunction(options.query)) {
            abort();
            buffer.ajax = options.query(data, options.success);
          } else {
            query(data);
          }
        }, delay);

        if (_.isFunction(waiting)) {
          waiting(data);
        }
      };

      delayQuery.query = function (data) {
        query(data);
      };

      return delayQuery;
    },

    ajaxBuffered: function (name, options) {
      if (app._xhrDebug) {
        console.log("ajaxBuffered", name, _.cloneDeep(options));
      }

      var data = _.clone(options.data);
      delete options.data;
      return app.ajaxBuffer(name, options)(data);
    },

    ajaxBufferClear: function (name) {
      delete app._xhrBuffers[name];
    },

    /* API */

    _appVersion: null,
    _apiParseHook: null,

    parseApi: function (response) {
      // Alters response in place.

      if (!(response && response.app)) {
        return;
      }

      var appData = response.app;
      delete response.app;

      if (app.appVersion && app.appVersion !== appData.version) {
        console.warn("App updated to " + appData.version + ". Reloading.");
        window.location.reload();
      }
      app.appVersion = appData.version;

      if (_.isFunction(app._apiParseHook)) {
        app._apiParseHook(response, appData);
      }
    },

    /* Cache */

    _cachePromises: {},
    _cacheValues: {},

    fetchCached: function (key, options) {
      // Returns a promise
      var deferred;

      if (!_.has(firma._cachePromises, key)) {
        deferred = new $.Deferred();
        firma._cachePromises[key] = deferred.promise();

        options.success = function (data, textStatus, jqXhr) {
          if (_.isUndefined(firma._cacheValues[key])) {
            firma._cacheValues[key] = data;
          }
          deferred.resolve(data);
        };
        options.error = function (jqXhr, textStatus, errorThrown) {
          console.error("fetchCached", key, jqXhr, textStatus, errorThrown);
          deferred.reject();
        };

        $.ajax(options);
      }

      return firma._cachePromises[key];
    },

    /* Template */

    template: {

      _templateUrl: null,
      _templateDict: null,

      _functionCache: {},
      _promiseCache: {},

      setUrl: function (path) {
        if (path.indexOf("/", path.length - 1) === -1) {
          path += "/";
        }
        app.template._templateUrl = path;
      },

      loadJson: function (url, callback) {
        $.ajax({
          url: url,
          success: function (response) {
            app.template._templateDict = response;
            callback();
          },
          error: function (jqXHR, textStatus, errorThrown) {
            console.error("Failed to load JSON: ", textStatus, errorThrown);
          }
        });

      },

      loadPromise: function (name) {
        var url = app.template._templateUrl + name;
        var cache = app.template._promiseCache;

        if (!_.has(cache, name)) {
          var deferred = new $.Deferred();

          $.ajax({
            url: url,
            success: function (response) {
              var f;
              try {
                f = _.template(response);
              } catch (e) {
                console.error("Failed to render template '" + name + "'.");
                throw e;
              }
              app.template._functionCache[name] = f;
              deferred.resolveWith(null, [f]);
            },
            error: function (jqXHR, textStatus, errorThrown) {
              deferred.reject();
            }
          });

          cache[name] = deferred.promise();
        }

        return cache[name];
      },

      load: function (nameList, callback) {
        var deferredList = [];
        _.each(nameList, function (name, i) {
          deferredList.push(app.template.loadPromise(name));
        });
        if (_.isFunction(callback)) {
          $.when.apply($, deferredList).then(callback);
        }
      },

      process: function (name, f, data, options) {
        var html;

        try {
          html = f(data);
        } catch (error) {
          console.error("Template function error: " + name);
          throw error.stack;
        }

        html = html.trim();

        if (options && _.has(options, "compact") && options.compact) {
          html = html.replace(/>\s+/gm, ">");
          html = html.replace(/\s+</gm, "<");
        }

        return html;
      },

      renderFromJson: function (name, data, callback, options) {
        // Return `true` on failure.

        if (!app.template._templateDict[name]) {
          console.error("Template " + name + " not found.");
          return;
        }

        var f = _.template(app.template._templateDict[name]);
        var html = app.template.process(name, f, data, options);
        if (_.isFunction(callback)) {
          callback(html);
          return;
        }
        return html;
      },

      renderSync: function (name, data, callback, options) {
        if (!_.isNull(app.template._templateDict)) {
          app.template.renderFromJson(name, data, callback, options);
          return;
        }

        var promise = app.template.loadPromise(name);
        promise.done(function (f) {
          var html = app.template.process(name, f, data, options);
          if (_.isFunction(callback)) {
            callback(html);
          }
        }).fail(function () {
          console.error("Template load error: " + app.template._templateUrl + name);
        });
      },

      render: function (name, data, options) {
        // Fails if template is not already loaded.

        if (!_.isNull(app.template._templateDict)) {
          return app.template.renderFromJson(name, data, undefined, options);
        }

        var promise = app.template._promiseCache[name];
        if (!promise) {
          console.error("Template '" + name + "' not loaded.");
        }
        var state = promise.state();
        if (state !== "resolved") {
          console.error("Template '" + name + "' failed to load: ." + state);
        }
        var f = app.template._functionCache[name];
        var html = app.template.process(name, f, data, options);
        return html;
      }
    }
  };

  return app;

})();
