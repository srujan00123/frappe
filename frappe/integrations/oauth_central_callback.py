# Copyright (c) 2025, Frappe Technologies and contributors
# License: MIT. See LICENSE

"""
Central OAuth callback handler for multi-tenant SaaS deployments.
This allows a single OAuth redirect URI to handle callbacks for multiple tenant sites.
"""

import json
from urllib.parse import urlencode, urlparse

import frappe
from frappe import _


@frappe.whitelist(allow_guest=True)
def google_calendar_callback(code=None, state=None, error=None):
	"""
	Central callback handler for Google Calendar OAuth.

	This endpoint receives the OAuth callback from Google and redirects to the
	appropriate tenant site to complete the authorization process.

	Args:
		code: Authorization code from Google
		state: JSON-encoded state containing tenant_site and other params
		error: Error code if authorization failed
	"""

	if error:
		frappe.respond_as_web_page(
			_("Authorization Failed"),
			_("Google Calendar authorization failed: {0}").format(error),
			indicator_color="red",
			http_status_code=400
		)
		return

	if not code or not state:
		frappe.respond_as_web_page(
			_("Invalid Request"),
			_("Missing authorization code or state parameter."),
			indicator_color="red",
			http_status_code=400
		)
		return

	try:
		# Decode the state parameter
		state_data = json.loads(state)
		tenant_site = state_data.get("tenant_site")
		google_calendar = state_data.get("google_calendar")

		if not tenant_site or not google_calendar:
			raise ValueError("Missing tenant_site or google_calendar in state")

		# Construct the redirect URL to the tenant site
		tenant_callback_url = (
			f"https://{tenant_site}"
			f"?cmd=frappe.integrations.doctype.google_calendar.google_calendar.google_callback"
			f"&code={code}"
			f"&google_calendar={google_calendar}"
		)

		# Redirect to tenant site to complete authorization
		frappe.local.response["type"] = "redirect"
		frappe.local.response["location"] = tenant_callback_url

	except Exception as e:
		frappe.log_error(
			title="Central OAuth Callback Error",
			message=f"Error processing OAuth callback: {str(e)}\nState: {state}"
		)
		frappe.respond_as_web_page(
			_("Authorization Error"),
			_("An error occurred while processing the authorization. Please try again."),
			indicator_color="red",
			http_status_code=500
		)


@frappe.whitelist(allow_guest=True)
def health_check():
	"""Simple health check endpoint"""
	return {"status": "ok", "service": "oauth_central_callback"}
