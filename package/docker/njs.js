function getRequestedDocumentPath(request) {
	let decodedPath = decodeURI(request.args["requested_document"])
	request.headersOut["x-requested-documents"] = decodedPath
	return decodedPath
}

function isAuthorized(userPrivileges) {
	var authorizedPrivileges = [
		"app:clinical",
		"app:patient-documents",
		"app:document-upload",
	]

	for (
		var privilegeIndex = 0;
		privilegeIndex < userPrivileges.length;
		privilegeIndex++
	)
		if (authorizedPrivileges.includes(userPrivileges[privilegeIndex].name))
			return true
	return false
}


function auth(request) {
	var documentPath = getRequestedDocumentPath(request)
	request.log(`Authenticating for Document request: ${documentPath}`)
	request.subrequest(
		`/openmrs/session/verify`,
		{ method: "GET" },
		function (res) {
			if (res.status === 200) {
				var jsonData = JSON.parse(res.responseBody)
				if (
					jsonData.authenticated && jsonData.user.privileges &&
					isAuthorized(jsonData.user.privileges)
				) {
					request.log(`User session ${jsonData.sessionId} is valid`)
					request.internalRedirect(
						`/document/fetch?requested_document=${documentPath}`
					)
				} else request.return(403)
				
			} else {
				request.error(`User session is invalid - Access Denied`)
				request.return(res.status, res.body)
			}
		}
	)
}

export default {
	getRequestedDocumentPath,
	auth,
}
