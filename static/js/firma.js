/*global window, $, _, URI */

function AjaxBuffer (options) {
  //
  // Options:
  //
  // `debug` If truthy, log debug messages to `console.log`.
  // `delay` Delay in ms before launching request
  //
  // `expire` Called when delay period starts.
  //   May be used to dim current content.
  // `unexpire` Called when request is called with query identical to last results,
  //   in which case `success` and `complete` are not called.
  //   May be used to undim expired content.
  // `data`: data for an initial request
  // `context`: context for an initial request
  //
  // `processRequest`
  // `processResponse`

  if (_.isUndefined(options)) {
    // Allow for inheritance.
    return;
  }

  var success = options.success;
  var error = options.error;
  var complete = options.complete;

  var self = this;

  if (this === window) {
    var e = new Error("AjaxBuffer called without `new` keyword");
    console.error(e.stack);
    throw e;
  }

  self.abort = options.abort;
  self.expire = options.expire;
  self.unexpire = options.unexpire;

  options = _.defaults(options || {}, {
    debug: false
  });

  self.name = options.name;
  self.debug = options.debug;
  self.delay = options.delay;

  self.state = undefined;

  delete options.success;
  delete options.error;
  delete options.complete;

  delete options.abort;
  delete options.expire;
  delete options.unexpire;

  delete options.name;
  delete options.delay;

  // Everything left in `options` is for `jQuery.ajax`.
  self.defaults = options;

  self.defaults.success = function (response, textStatus, request, context) {
    self.log("defaults.success", response, context);
    if (_.isFunction(self.processResponse)) {
      self.processResponse(response);
    }
    if (_.isFunction(success)) {
      success(response, textStatus, request, context);
    }
  };

  self.defaults.error = function (jqXhr, status, err, context) {
    if (status === "abort") {
      self.log("defaults.abort");
      if (_.isFunction(self.abort)) {
        self.abort(jqXhr, status, err, context);
      }
      return;
    }

    self.log("defaults.error", jqXhr, context);
    if (_.isFunction(error)) {
      error(jqXhr, status, err, context);
    } else {
      console.error("Unhandled AJAX error", jqXhr, status, err);
    }
  };

  self.defaults.complete = function (jqXhr, status, context) {
    self.log("defaults.complete", jqXhr, context);
    delete self.state.xhr;
    if (_.isFunction(complete)) {
      complete(jqXhr, status, context);
    }
  };

  self.reset();
}

AjaxBuffer.prototype = {
  log: function () {
    var args = ["AjaxBuffer"];
    if (!this.debug) {
      return;
    }
    if (this.name) {
      args.push(this.name);
    }
    args = args.concat(Array.prototype.slice.call(arguments, 0));
    console.log.apply(console, args);
  },

  reset: function (args) {
    this.log("reset");
    this.abortTimeout();
    this.abortRequest();
    this.state = {
      timeout: null,
      xhr: null,
      deferred: null,
      promise: null,
      timeoutData: undefined,  // Input data for last timeout
      requestData: undefined,  // Input data for last request
      resultData: undefined    // Input data for last result
    };
  },

  abortTimeout: function () {
    if (this.state && this.state.timeout) {
      this.log("aborting incomplete timeout");
      clearTimeout(this.state.timeout);
      this.state.deferred.reject();
      this.state.timeout = null;
      this.state.deferred = null;
      this.state.promise = null;
      this.state.timeoutData = undefined;
    }
  },

  abortRequest: function () {
    if (this.state && this.state.xhr) {
      this.log("aborting incomplete request");
      this.state.xhr.abort();
      this.state.xhr = null;
      this.state.requestData = undefined;
    }
  },

  request: function (options) {
    //
    // Options:
    //
    // `data`: Data to be sent as JSON
    // `context` Javascript objects (eg. DOM elements, closures, callbacks)
    //   to be sent back to the `success` callback.
    // `delay`: If defined, override default delay
    //

    var self = this;
    var data, context;

    options = options || {};

    if (!_.isUndefined(options.data)) {
      data = _.cloneDeep(options.data);
    } else if (!_.isUndefined(self.defaults.data)) {
      data = self.defaults.data;
    } else {
      data = null;  // `data` may not be `undefined`.
    }

    context = _.extend(options.context, {
      data: data
    });

    delete options.context;

    this.log("request", this.state, options, context);
    this.log("delay", options.delay, this.delay);

    options.delay = _.isUndefined(options.delay) ? this.delay : options.delay;

    var success = function (response, textStatus, request) {
      self.log("request > success", response, context);
      self.state.resultData = _.cloneDeep(data);
      self.defaults.success(response, textStatus, request, context);
    };

    var error = function (jqXhr, status, err) {
      self.log("request > error", jqXhr, status, err);
      self.state.resultData = undefined;
      self.defaults.error(jqXhr, status, err, context);
    };

    var complete = function (jqXhr, status) {
      self.log("request > complete", jqXhr, status);
      self.state.xhr = null;
      self.state.requestData = undefined;
      self.defaults.complete(jqXhr, status, context);
    };

    var request = function () {
      var ajaxOptions = _.cloneDeep(self.defaults);
      if (options.url) {
        ajaxOptions.url = options.url;
      }
      _.extend(ajaxOptions, {
        data: data,
        success: success,
        error: error,
        complete: complete,
      });

      self.log("actual request", self.state, ajaxOptions);

      self.state.requestData = _.cloneDeep(data);
      if (_.isFunction(self.processRequest)) {
        ajaxOptions.data = self.processRequest(_.cloneDeep(ajaxOptions.data));
      }
      self.state.xhr = $.ajax(ajaxOptions);

      return self.state.xhr;
    };

    var immediateRequest = function () {
      self.log("immediate request", self.state, options);

      if (_.isFunction(self.expire)) {
        self.expire(_.cloneDeep(data));
      }
      self.abortTimeout();
      self.abortRequest();
      return request();
    };

    var delayedRequest = function () {
      self.log("delayedRequest", self.state, options);

      if (self.state.xhr && _.isEqual(data, self.state.requestData)) {
        self.log("equal request");
        return self.state.xhr;
      }

      if (self.state.timeout && _.isEqual(data, self.state.timeoutData)) {
        self.log("equal timeout");
        return self.state.promise;
      }

      self.abortTimeout();
      self.abortRequest();
      self.state.timeoutData = _.cloneDeep(data);
      self.state.deferred = new $.Deferred();
      self.state.promise = self.state.deferred.promise();

      if (_.isFunction(self.expire)) {
        self.expire(data);
      }

      self.state.timeout = setTimeout(function () {
        self.log("timeout fire", options.delay);
        request()
          .done(self.state.deferred.resolve)
          .fail(self.state.deferred.reject)
        ;
      }, options.delay);
      self.log("timeout set", options.delay);

      return self.state.promise;
    };

    if (_.isEqual(data, this.state.resultData)) {
      this.log("equal result");
      this.abortTimeout();
      this.abortRequest();
      if (_.isFunction(this.unexpire)) {
        this.unexpire();
      }
      // Nothing to do, resolve immediately with no data:
      return Promise.resolve();
    }

    if (options.delay) {
      return delayedRequest();
    }

    return immediateRequest();
  }
};

var firma = (function () {
  "use strict";

  var app;

  app = {

    /* XHR */

    _xhr: {},
    _xhrDebug: false,
    _xhrBuffers: {},

    ajax: function (options) {
      if (app._xhrDebug) {
        console.log("ajax", name, options);
      }
      options = _.defaults(options || {}, {
        debug: undefined,
      });
      return new AjaxBuffer(options).request();
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
      var delayQuery = function (data, context, noRequest) {
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
          app.ajax(_.extend(options, {
            name: name,
            data: data
          }));
        };

        if (!noRequest) {
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
        }
      };

      delayQuery.query = function (data) {
        query(data);
      };

      return delayQuery;
    },

    ajaxBuffered: function (options) {
      if (app._xhrDebug) {
        console.log("ajaxBuffered", _.cloneDeep(options));
      }

      var name = _.clone(options.name);
      var data = _.clone(options.data);
      delete options.name;
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
          error: function (jqXhr, textStatus, errorThrown) {
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
            error: function (jqXhr, textStatus, errorThrown) {
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
    },

    // Navigation

    regexRoute: function (routes, path, callback) {
      var routeMatch = false;
      var groups = false;
      _.forEach(routes, function (route, i) {
        var regex = route.regex;
        var regexMatch = regex.exec(path);
        if (regexMatch) {
          groups = [];
          for (var j = 1; j < regexMatch.length; j++) {
            groups.push(regexMatch[j]);
          }
          routeMatch = route;
          return false;
        }
      });

      if (routeMatch === false) {
        console.error("No route for path:", path);
      }

      callback(routeMatch, groups);
    },

    urlRemoveRoot: function (root, path) {
      if ((path + "/") == root) {
        path = path.substring(root.length - 1);
      } else if (path.indexOf(root) === 0) {
        path = path.substring(root.length);
      }
      if (path.indexOf("/") !== 0) {
        path = "/" + path;
      }
      return path;
    },

    uriToResource: function (root, uri, options) {
      var resource;

      options = _.extend({
        query: true
      }, options);

      if (_.isNil(uri)) {
        uri = window.location;
      }

      if (options.query) {
        resource = URI(uri).resource();
      } else {
        resource = URI(uri).path();
      }

      resource = firma.urlRemoveRoot(root, resource);

      return resource;
    },

    resourceToUri: function (root, resource) {
      return root + resource;
    },

    navigate: function (root, resource, options) {
      // To be called when the user initiates navigation.
      // -   Update the URL immediately
      // -   Initiate site routing in the `onTrigger` callback
      // -   Set a null page state, since it won't be loaded yet.

      var currentResource = firma.uriToResource(root);

      options = _.extend({
        trigger: true,
        replace: false,
        reload: false
      }, options);

      if (resource === currentResource) {
        if (options.reload) {
          options.replace = true;
        } else {
          return;
        }
      }

      var url = firma.resourceToUri(root, resource);

      if (options.replace) {
        window.history.replaceState(null, null, url);
      } else {
        window.history.pushState({}, null, url);
      }

      if (options.trigger && _.isFunction(options.onTrigger)) {
        options.onTrigger();
      }
    },

    setCompleteState: function (state) {
      // To be called when the page data is fully loaded.
      // -   Save the page content state to `sessionStorage`
      // -   Set the history state to the localStorage key
      // -   Automated test browsers can watch `window.history.state` for
      //     changes to determine when new pages have fully loaded.
      //
      // `state` must be an object.

      var index = 0;
      var indexStr = window.sessionStorage.getItem("firmaStateIndex");
      var key, serializedState;

      if (_.isNull(state)) {
        window.history.replaceState(null, null);
        return null;
      }
      if (!_.isObject(state)) {
        throw new Error("Parameter `state` of `firma.setCompleteState` must be an object or `null`.");
      }

      if (!_.isNil(indexStr)) {
        index = JSON.parse(indexStr) + 1;
      }

      key = "firmaState-" + index;

      serializedState = JSON.stringify(state);

      window.sessionStorage.setItem(key, serializedState);
      window.sessionStorage.setItem("firmaStateIndex", JSON.stringify(index));

      window.history.replaceState(key, null);

      return key;
    },

    getState: function (key) {
      var stateStr = window.sessionStorage.getItem(key);
      var keyAux, state, stateAuxStr, stateAux;

      if (_.isNil(key)) {
        return key;
      }

      if (_.isNil(stateStr)) {
        console.warn("Failed to retrieve state", key);
        return undefined;
      }

      keyAux = key + "-aux";
      state = JSON.parse(stateStr);
      stateAuxStr = window.sessionStorage.getItem(keyAux);
      if (!_.isNil(stateAuxStr)) {
        stateAux = JSON.parse(stateAuxStr);
        _.extend(state, stateAux);
      }

      return state;
    },

    setAuxState: function (state) {
      // To be called when changing auxilliary data (eg. scroll position) to be
      // added to state when retrieving it.
      //
      // Does not involve reading, updating and writing saved state.
      // Previous aux state will be overwritten.
      //
      // `state` must be an object.
      //
      // If the value of `history.state` is:
      // -   an object, update it with `state`
      // -   anything else, throw an error
      //

      var key = window.history.state;

      if (_.isNil(key)) {
        console.warn("Cannot update null state");
        return;
      }

      if (!_.isObject(state)) {
        throw new Error("Parameter `state` of `firma.setAuxState` must be an object.");
      }

      var keyAux = key + "-aux";

      window.sessionStorage.setItem(keyAux, JSON.stringify(state));
    }

  };

  return app;

})();
