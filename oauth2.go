// Package oauth2 provides an `http.Handler` that uses an OAuth2-esque API to
// handle the issuance of access and refresh tokens.
//
// The handler is "OAuth2-esque" in that normally OAuth2 provides a way for a
// service to obtain credentials that gives the service some limited access to
// a user's account after the user authenticates directly with the service
// using their credentials. It's a way of delegating a new or existing session
// to a third party. This handler does not do that; it is for the establishing
// of a session, and in theory could be repurposed or extended in the future to
// allow for a user to delegate access to a third party using a new or
// established session, as intended by OAuth2.
//
// "Why is this called oauth2 if it's not actually implementing OAuth2?" and
// "why make something that looks like OAuth2 but is not OAuth2?" are both
// reasonable questions with unsatisfactory answers. The package is named as it
// is because the interface is based on OAuth2 and that's the easiest way to
// identify it, when there could conceivably be interfaces not based on OAuth2
// at some point. As for why it's based on OAuth2, it's because the desired
// user experience ("click login, enter my email, get a code emailed to me,
// exchange that code for a session") looks a bit like the OAuth2 user
// experience ("click login, enter my OAuth2 provider, authenticate if
// necessary, get a code, exchange the code for a session") if you squint a
// bit, and having a framework that had thought through the security properties
// of the framework was useful.
//
// Use this package by creating a `Service` struct and calling its `Server`
// method to get the `http.Handler`. The `http.Handler` should be served
// through a muxer using the same path as the `prefix` passed to `Server`.
package oauth2
