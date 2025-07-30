package domain

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	domainfern "github.com/Method-Security/networkscan/generated/go/enumerate/domain"

	// External
	"github.com/go-ldap/ldap/v3"
)

type LibraryEnumerateDomain struct{}

func (l *LibraryEnumerateDomain) EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string) {
	var errors []string

	ldapPort := 389
	useSSL := false
	config := domainfern.EnumerateDomainConfig{
		Target:            target,
		Domain:            "WORKGROUP", // Default domain for anonymous enumeration
		LdapPort:          &ldapPort,
		UseSsl:            &useSSL,
		Timeout:           30,
		CollectionMethods: []domainfern.CollectionMethod{domainfern.CollectionMethodGroup},
	}

	result, errs := l.enumerateDomain(ctx, config)
	errors = append(errors, errs...)

	if result == nil {
		return nil, errors
	}

	details := &enumeratefern.EnumerateServiceDetails{
		EnumerateDomainDetails: result,
	}

	return details, errors
}

// EnumerateDomain performs domain enumeration based on the provided configuration
func (l *LibraryEnumerateDomain) EnumerateDomain(ctx context.Context, config domainfern.EnumerateDomainConfig) (*domainfern.EnumerateDomainResult, []string) {
	return l.enumerateDomain(ctx, config)
}

func (l *LibraryEnumerateDomain) enumerateDomain(ctx context.Context, config domainfern.EnumerateDomainConfig) (*domainfern.EnumerateDomainResult, []string) {
	var errors []string

	conn, err := l.connectToLDAP(config)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to connect to LDAP: %v", err))
		return nil, errors
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("[ERROR] Failed to close LDAP connection: %v", err)
		}
	}()

	baseDN, err := l.getBaseDN(conn, config.Target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to determine base DN: %v", err))
		return nil, errors
	}

	result := &domainfern.EnumerateDomainResult{
		TotalObjects: 0,
	}

	for _, collectionMethod := range config.CollectionMethods {
		switch collectionMethod {
		case domainfern.CollectionMethodGroup:
			// Enumerate groups, users, and basic membership information
			groups, errs := l.enumerateGroups(conn, baseDN, config.MaxResults)
			if groups != nil {
				groupsResult := &domainfern.DomainGroupsResult{
					Data: *groups,
					Meta: &domainfern.DomainDataMeta{
						Methods: 0,
						Type:    "groups",
						Count:   len(*groups),
						Version: 5,
					},
				}
				result.Groups = groupsResult
				result.TotalObjects += len(*groups)
			}
			errors = append(errors, errs...)

			users, errs := l.enumerateUsers(conn, baseDN, config.MaxResults)
			if users != nil {
				usersResult := &domainfern.DomainUsersResult{
					Data: *users,
					Meta: &domainfern.DomainDataMeta{
						Methods: 0,
						Type:    "users",
						Count:   len(*users),
						Version: 5,
					},
				}
				result.Users = usersResult
				result.TotalObjects += len(*users)
			}
			errors = append(errors, errs...)

		case domainfern.CollectionMethodTrusts:
			// Enumerate domain trusts
			trusts, errs := l.enumerateDomainTrusts(conn, baseDN, config.MaxResults)
			if trusts != nil {
				result.DomainTrusts = *trusts
				result.TotalObjects += len(*trusts)
			}
			errors = append(errors, errs...)

		case domainfern.CollectionMethodObjectprops:
			// Enumerate organizational units and GPOs
			ous, errs := l.enumerateOrganizationalUnits(conn, baseDN, config.MaxResults)
			if ous != nil {
				result.OrganizationalUnits = *ous
				result.TotalObjects += len(*ous)
			}
			errors = append(errors, errs...)

			gpos, errs := l.enumerateGroupPolicyObjects(conn, baseDN, config.MaxResults)
			if gpos != nil {
				result.GroupPolicyObjects = *gpos
				result.TotalObjects += len(*gpos)
			}
			errors = append(errors, errs...)

		case domainfern.CollectionMethodContainer:
			// Enumerate computers and domain controllers
			computers, errs := l.enumerateComputers(conn, baseDN, config.MaxResults)
			if computers != nil {
				result.Computers = *computers
				result.TotalObjects += len(*computers)
			}
			errors = append(errors, errs...)

			dcs, errs := l.enumerateDomainControllers(conn, baseDN, config.MaxResults)
			if dcs != nil {
				result.DomainControllers = *dcs
				result.TotalObjects += len(*dcs)
			}
			errors = append(errors, errs...)

		case domainfern.CollectionMethodLocaladmin:
			// Currently not implemented - would require connecting to computers
			log.Printf("[INFO] Local admin enumeration not yet implemented (requires computer connections)")

		case domainfern.CollectionMethodSession:
			// Currently not implemented - would require connecting to computers
			log.Printf("[INFO] Session enumeration not yet implemented (requires computer connections)")

		case domainfern.CollectionMethodAcl:
			// Currently not implemented - would require ACL parsing
			log.Printf("[INFO] ACL enumeration not yet implemented")

		case domainfern.CollectionMethodDefault:
			// Expand to default methods: group, localadmin, session, trusts
			config.CollectionMethods = append(config.CollectionMethods,
				domainfern.CollectionMethodGroup,
				domainfern.CollectionMethodLocaladmin,
				domainfern.CollectionMethodSession,
				domainfern.CollectionMethodTrusts)

		case domainfern.CollectionMethodAll:
			// Expand to all methods except loggedon
			config.CollectionMethods = append(config.CollectionMethods,
				domainfern.CollectionMethodGroup,
				domainfern.CollectionMethodLocaladmin,
				domainfern.CollectionMethodSession,
				domainfern.CollectionMethodTrusts,
				domainfern.CollectionMethodObjectprops,
				domainfern.CollectionMethodAcl,
				domainfern.CollectionMethodContainer)

		case domainfern.CollectionMethodDconly:
			// Expand to DC-only methods: group, trusts, objectprops, acl, container
			config.CollectionMethods = append(config.CollectionMethods,
				domainfern.CollectionMethodGroup,
				domainfern.CollectionMethodTrusts,
				domainfern.CollectionMethodObjectprops,
				domainfern.CollectionMethodAcl,
				domainfern.CollectionMethodContainer)

		default:
			// For other methods (dcom, rdp, psremote, loggedon, experimental), log that they're not implemented
			log.Printf("[INFO] Collection method %s not yet implemented", collectionMethod)
		}
	}

	return result, errors
}

func (l *LibraryEnumerateDomain) connectToLDAP(config domainfern.EnumerateDomainConfig) (*ldap.Conn, error) {
	port := 389
	if config.LdapPort != nil {
		port = *config.LdapPort
	}

	var conn *ldap.Conn
	var err error

	if config.UseSsl != nil && *config.UseSsl {
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", config.Target, port), &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.Target, port))
	}

	if err != nil {
		return nil, err
	}

	conn.SetTimeout(time.Duration(config.Timeout) * time.Second)

	if config.Username != nil && config.Password != nil {
		// Format username as DOMAIN\username
		bindUsername := fmt.Sprintf("%s\\%s", strings.ToUpper(config.Domain), *config.Username)
		log.Printf("[INFO] Attempting authentication with username: %s", bindUsername)

		err = conn.Bind(bindUsername, *config.Password)
		if err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("[ERROR] Failed to close LDAP connection: %v", closeErr)
			}
			return nil, fmt.Errorf("authentication failed: %v", err)
		}
	} else {
		err = conn.UnauthenticatedBind("")
		if err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("[ERROR] Failed to close LDAP connection: %v", closeErr)
			}
			return nil, fmt.Errorf("anonymous bind failed: %v", err)
		}
	}

	return conn, nil
}

func (l *LibraryEnumerateDomain) getBaseDN(conn *ldap.Conn, target string) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectclass=*)",
		[]string{"namingContexts"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", err
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("no naming contexts found")
	}

	namingContexts := sr.Entries[0].GetAttributeValues("namingContexts")
	if len(namingContexts) == 0 {
		return "", fmt.Errorf("no naming contexts available")
	}

	for _, nc := range namingContexts {
		if strings.Contains(nc, "DC=") {
			return nc, nil
		}
	}

	return "", fmt.Errorf("no domain naming context found")
}

func (l *LibraryEnumerateDomain) enumerateUsers(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.DomainUser, []string) {
	var errors []string
	var users []*domainfern.DomainUser

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	// Extract domain information
	domain := l.extractDomainFromBaseDN(baseDN)
	domainSID := l.extractDomainSID(conn, baseDN)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(&(objectClass=user)(objectCategory=person))",
		[]string{
			"distinguishedName", "sAMAccountName", "userPrincipalName", "displayName",
			"description", "objectSid", "userAccountControl", "accountExpires",
			"lastLogon", "pwdLastSet", "memberOf", "adminCount", "servicePrincipalName",
			"primaryGroupID",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search users: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		user := &domainfern.DomainUser{}

		// Extract and convert binary SID to readable format
		var objectSID string
		if sidBytes := entry.GetRawAttributeValue("objectSid"); len(sidBytes) > 0 {
			objectSID = l.convertSIDToString(string(sidBytes))
		}
		user.ObjectIdentifier = objectSID

		// Set PrimaryGroupSID
		if primaryGroupID := entry.GetAttributeValue("primaryGroupID"); primaryGroupID != "" {
			primaryGroupSID := fmt.Sprintf("%s-%s", domainSID, primaryGroupID)
			user.PrimaryGroupSid = &primaryGroupSID
		}

		// Create properties object
		properties := &domainfern.DomainUserProperties{}

		// Required fields
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		if upn := entry.GetAttributeValue("userPrincipalName"); upn != "" {
			properties.Name = strings.ToUpper(upn)
		} else {
			properties.Name = fmt.Sprintf("%s@%s", strings.ToUpper(samAccountName), domain)
		}
		properties.Domain = domain
		properties.Domainsid = domainSID
		properties.Distinguishedname = strings.ToUpper(entry.GetAttributeValue("distinguishedName"))

		// Set defaults for required boolean fields
		properties.Unconstraineddelegation = false
		properties.Trustedtoauth = false
		properties.Passwordnotreqd = false

		// Optional fields
		if displayName := entry.GetAttributeValue("displayName"); displayName != "" {
			properties.Displayname = &displayName
		}
		if description := entry.GetAttributeValue("description"); description != "" {
			properties.Description = &description
		}
		if samAccountName != "" {
			properties.Samaccountname = &samAccountName
		}

		// Parse userAccountControl for enabled status
		if uacStr := entry.GetAttributeValue("userAccountControl"); uacStr != "" {
			if uac, err := strconv.Atoi(uacStr); err == nil {
				enabled := (uac & 0x0002) == 0 // UF_ACCOUNTDISABLE = 0x0002
				properties.Enabled = &enabled

				// Check for password not required flag
				passwordNotReqd := (uac & 0x0020) != 0 // UF_PASSWD_NOTREQD = 0x0020
				properties.Passwordnotreqd = passwordNotReqd
			}
		}

		// Keep timestamps as raw values like reference
		if lastLogon := entry.GetAttributeValue("lastLogon"); lastLogon != "" {
			properties.Lastlogon = &lastLogon
		}
		if pwdLastSet := entry.GetAttributeValue("pwdLastSet"); pwdLastSet != "" {
			properties.Pwdlastset = &pwdLastSet
		}

		// Get admin count
		if adminCountStr := entry.GetAttributeValue("adminCount"); adminCountStr != "" {
			if adminCount, err := strconv.Atoi(adminCountStr); err == nil {
				properties.Admincount = &adminCount
			}
		}

		// Get service principal names
		if spnValues := entry.GetAttributeValues("servicePrincipalName"); len(spnValues) > 0 {
			properties.Serviceprincipalnames = spnValues
		}

		user.Properties = properties

		// Initialize empty arrays as required by reference format
		user.AllowedToDelegate = []string{}
		user.Aces = []string{}
		user.SpnTargets = []string{}
		user.HasSidHistory = []string{}
		user.IsDeleted = false

		users = append(users, user)
	}

	log.Printf("[INFO] Enumerated %d users", len(users))
	return &users, errors
}

func (l *LibraryEnumerateDomain) enumerateGroups(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.DomainGroup, []string) {
	var errors []string
	var groups []*domainfern.DomainGroup

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	// Extract domain information
	domain := l.extractDomainFromBaseDN(baseDN)
	domainSID := l.extractDomainSID(conn, baseDN)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=group)",
		[]string{
			"distinguishedName", "sAMAccountName", "description", "objectSid",
			"groupType", "member", "memberOf", "adminCount",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search groups: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		group := &domainfern.DomainGroup{}

		// Extract and convert binary SID to readable format
		var objectSID string
		if sidBytes := entry.GetRawAttributeValue("objectSid"); len(sidBytes) > 0 {
			objectSID = l.convertSIDToString(string(sidBytes))
		}
		group.ObjectIdentifier = objectSID

		// Create properties object
		properties := &domainfern.DomainGroupProperties{}

		// Required fields
		samAccountName := entry.GetAttributeValue("sAMAccountName")
		properties.Name = fmt.Sprintf("%s@%s", strings.ToUpper(samAccountName), domain)
		properties.Domain = domain
		properties.Domainsid = domainSID
		properties.Distinguishedname = strings.ToUpper(entry.GetAttributeValue("distinguishedName"))

		// Determine if this is a high-value group
		properties.Highvalue = l.isHighValueGroup(samAccountName)

		// Optional fields
		if description := entry.GetAttributeValue("description"); description != "" {
			properties.Description = &description
		}
		if adminCountStr := entry.GetAttributeValue("adminCount"); adminCountStr != "" {
			if adminCount, err := strconv.Atoi(adminCountStr); err == nil {
				properties.Admincount = &adminCount
			}
		}

		group.Properties = properties

		// Process members to create Members array with ObjectIdentifier/ObjectType format
		var members []*domainfern.GroupMember
		memberDNS := entry.GetAttributeValues("member")
		for _, memberDN := range memberDNS {
			// Get the member's SID by doing a lookup
			memberSID := l.getMemberSID(conn, memberDN)
			if memberSID != "" {
				member := &domainfern.GroupMember{
					ObjectIdentifier: memberSID,
					ObjectType:       l.determineMemberType(memberDN), // "User" or "Group"
				}
				members = append(members, member)
			}
		}
		group.Members = members

		// Initialize empty arrays as required by reference format
		group.Aces = []string{}
		group.IsDeleted = false

		groups = append(groups, group)
	}

	log.Printf("[INFO] Enumerated %d groups", len(groups))
	return &groups, errors
}

// isHighValueGroup determines if a group is considered high value
func (l *LibraryEnumerateDomain) isHighValueGroup(samAccountName string) bool {
	highValueGroups := []string{
		"ADMINISTRATORS", "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
		"ACCOUNT OPERATORS", "SERVER OPERATORS", "PRINT OPERATORS", "BACKUP OPERATORS",
		"DOMAIN CONTROLLERS",
	}

	upperSAM := strings.ToUpper(samAccountName)
	for _, hvGroup := range highValueGroups {
		if upperSAM == hvGroup {
			return true
		}
	}
	return false
}

// getMemberSID gets the SID of a member by DN
func (l *LibraryEnumerateDomain) getMemberSID(conn *ldap.Conn, memberDN string) string {
	searchRequest := ldap.NewSearchRequest(
		memberDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		return ""
	}

	if sidBytes := sr.Entries[0].GetRawAttributeValue("objectSid"); len(sidBytes) > 0 {
		return l.convertSIDToString(string(sidBytes))
	}
	return ""
}

// determineMemberType determines if a member is a User or Group based on DN
func (l *LibraryEnumerateDomain) determineMemberType(memberDN string) string {
	// Simple heuristic: if DN contains "OU=Users" or "CN=Users", likely a user
	// If it contains group-related OUs or is a group object, it's a group
	upperDN := strings.ToUpper(memberDN)
	if strings.Contains(upperDN, "OU=USERS") || strings.Contains(upperDN, "CN=USERS") ||
		strings.Contains(upperDN, "OU=ADI_USERS") || strings.Contains(upperDN, "OU=ADI_SERVICEACCOUNTS") {
		return "User"
	}
	return "Group"
}

func (l *LibraryEnumerateDomain) enumerateComputers(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.DomainComputer, []string) {
	var errors []string
	var computers []*domainfern.DomainComputer

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=computer)",
		[]string{
			"distinguishedName", "sAMAccountName", "dNSHostName", "description",
			"objectSid", "operatingSystem", "operatingSystemVersion", "userAccountControl",
			"lastLogon", "servicePrincipalName", "serverReferenceBL",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search computers: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		computer := &domainfern.DomainComputer{
			DistinguishedName: entry.DN,
			SamAccountName:    l.getAttributeValue(entry, "sAMAccountName"),
			ObjectSid:         l.convertSIDToString(l.getAttributeValue(entry, "objectSid")),
		}

		if dnsHostName := l.getAttributeValue(entry, "dNSHostName"); dnsHostName != "" {
			computer.DnsHostName = &dnsHostName
		}
		if desc := l.getAttributeValue(entry, "description"); desc != "" {
			computer.Description = &desc
		}
		if os := l.getAttributeValue(entry, "operatingSystem"); os != "" {
			computer.OperatingSystem = &os
		}
		if osVer := l.getAttributeValue(entry, "operatingSystemVersion"); osVer != "" {
			computer.OperatingSystemVersion = &osVer
		}

		uac := l.getAttributeValue(entry, "userAccountControl")
		if uac != "" {
			if uacInt, err := strconv.Atoi(uac); err == nil {
				computer.Enabled = (uacInt & 0x0002) == 0
			}
		}

		if lastLogon := l.getAttributeValue(entry, "lastLogon"); lastLogon != "" {
			convertedTime := l.convertFileTime(lastLogon)
			computer.LastLogon = &convertedTime
		}

		spns := entry.GetAttributeValues("servicePrincipalName")
		if len(spns) > 0 {
			computer.ServicePrincipalNames = spns
		}

		serverRef := entry.GetAttributeValues("serverReferenceBL")
		computer.IsDomainController = len(serverRef) > 0

		computers = append(computers, computer)
	}

	log.Printf("[INFO] Enumerated %d computers", len(computers))
	return &computers, errors
}

func (l *LibraryEnumerateDomain) enumerateDomainControllers(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.DomainController, []string) {
	var errors []string
	var dcs []*domainfern.DomainController

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(&(objectClass=computer)(serverReferenceBL=*))",
		[]string{
			"distinguishedName", "sAMAccountName", "dNSHostName", "siteName",
			"operatingSystem", "operatingSystemVersion", "serverReferenceBL",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search domain controllers: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		dc := &domainfern.DomainController{
			DistinguishedName: entry.DN,
			SamAccountName:    l.getAttributeValue(entry, "sAMAccountName"),
			DnsHostName:       l.getAttributeValue(entry, "dNSHostName"),
		}

		if siteName := l.getAttributeValue(entry, "siteName"); siteName != "" {
			dc.SiteName = &siteName
		}
		if os := l.getAttributeValue(entry, "operatingSystem"); os != "" {
			dc.OperatingSystem = &os
		}
		if osVer := l.getAttributeValue(entry, "operatingSystemVersion"); osVer != "" {
			dc.OperatingSystemVersion = &osVer
		}

		roles := entry.GetAttributeValues("serverReferenceBL")
		if len(roles) > 0 {
			dc.Roles = roles
		}

		dcs = append(dcs, dc)
	}

	log.Printf("[INFO] Enumerated %d domain controllers", len(dcs))
	return &dcs, errors
}

func (l *LibraryEnumerateDomain) enumerateOrganizationalUnits(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.OrganizationalUnit, []string) {
	var errors []string
	var ous []*domainfern.OrganizationalUnit

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=organizationalUnit)",
		[]string{
			"distinguishedName", "name", "description", "gPLink",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search organizational units: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		ou := &domainfern.OrganizationalUnit{
			DistinguishedName: entry.DN,
			Name:              l.getAttributeValue(entry, "name"),
		}

		if desc := l.getAttributeValue(entry, "description"); desc != "" {
			ou.Description = &desc
		}

		gpoLinks := entry.GetAttributeValues("gPLink")
		if len(gpoLinks) > 0 {
			ou.GpoLinks = gpoLinks
		}

		ous = append(ous, ou)
	}

	log.Printf("[INFO] Enumerated %d organizational units", len(ous))
	return &ous, errors
}

func (l *LibraryEnumerateDomain) enumerateGroupPolicyObjects(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.GroupPolicyObject, []string) {
	var errors []string
	var gpos []*domainfern.GroupPolicyObject

	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		sizeLimit,
		0,
		false,
		"(objectClass=groupPolicyContainer)",
		[]string{
			"distinguishedName", "displayName", "description", "gPCFileSysPath", "versionNumber",
		},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to search group policy objects: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		gpo := &domainfern.GroupPolicyObject{
			DistinguishedName: entry.DN,
			DisplayName:       l.getAttributeValue(entry, "displayName"),
		}

		if desc := l.getAttributeValue(entry, "description"); desc != "" {
			gpo.Description = &desc
		}
		if gpcPath := l.getAttributeValue(entry, "gPCFileSysPath"); gpcPath != "" {
			gpo.GpcFileSysPath = &gpcPath
		}
		if version := l.getAttributeValue(entry, "versionNumber"); version != "" {
			if versionInt, err := strconv.Atoi(version); err == nil {
				gpo.VersionNumber = &versionInt
			}
		}

		gpos = append(gpos, gpo)
	}

	log.Printf("[INFO] Enumerated %d group policy objects", len(gpos))
	return &gpos, errors
}

func (l *LibraryEnumerateDomain) getAttributeValue(entry *ldap.Entry, attribute string) string {
	values := entry.GetAttributeValues(attribute)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// convertSIDToString converts a binary SID to its string representation (S-1-5-21-...)
func (l *LibraryEnumerateDomain) convertSIDToString(sidBytes string) string {
	if len(sidBytes) < 8 {
		return sidBytes // Return as-is if too short
	}

	// Convert string to bytes
	data := []byte(sidBytes)

	// Check if this looks like a binary SID (starts with revision 1)
	if len(data) < 8 || data[0] != 1 {
		return sidBytes // Return as-is if not a binary SID
	}

	revision := data[0]
	subAuthorityCount := data[1]

	if len(data) < int(8+4*subAuthorityCount) {
		return sidBytes // Return as-is if data is too short
	}

	// Extract identifier authority (6 bytes, big-endian)
	identifierAuthority := uint64(0)
	for i := 2; i < 8; i++ {
		identifierAuthority = (identifierAuthority << 8) | uint64(data[i])
	}

	// Build SID string
	sidString := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)

	// Extract sub-authorities (4 bytes each, little-endian)
	for i := 0; i < int(subAuthorityCount); i++ {
		offset := 8 + i*4
		if offset+4 <= len(data) {
			subAuthority := uint32(data[offset]) |
				uint32(data[offset+1])<<8 |
				uint32(data[offset+2])<<16 |
				uint32(data[offset+3])<<24
			sidString += fmt.Sprintf("-%d", subAuthority)
		}
	}

	return sidString
}

// convertGroupType converts numeric group type to readable description
func (l *LibraryEnumerateDomain) convertGroupType(groupTypeStr string) string {
	if groupTypeStr == "" {
		return ""
	}

	groupType, err := strconv.ParseInt(groupTypeStr, 10, 32)
	if err != nil {
		return groupTypeStr // Return original if parsing fails
	}

	// Group Type flags (from Microsoft documentation)
	groupTypeFlags := make([]string, 0)

	// Security vs Distribution
	if groupType&0x80000000 != 0 {
		groupTypeFlags = append(groupTypeFlags, "Security")
	} else {
		groupTypeFlags = append(groupTypeFlags, "Distribution")
	}

	// Scope
	if groupType&0x00000004 != 0 {
		groupTypeFlags = append(groupTypeFlags, "Domain Local")
	} else if groupType&0x00000008 != 0 {
		groupTypeFlags = append(groupTypeFlags, "Universal")
	} else {
		groupTypeFlags = append(groupTypeFlags, "Global")
	}

	return strings.Join(groupTypeFlags, " ") + fmt.Sprintf(" (%s)", groupTypeStr)
}

// convertFileTime converts Windows FILETIME (100-nanosecond intervals since 1601-01-01) to readable format
func (l *LibraryEnumerateDomain) convertFileTime(fileTimeStr string) string {
	if fileTimeStr == "" || fileTimeStr == "0" || fileTimeStr == "9223372036854775807" {
		return fileTimeStr // Return special values as-is
	}

	fileTime, err := strconv.ParseInt(fileTimeStr, 10, 64)
	if err != nil {
		return fileTimeStr // Return original if parsing fails
	}

	// Convert from Windows FILETIME to Unix timestamp
	// FILETIME epoch: January 1, 1601
	// Unix epoch: January 1, 1970
	// Difference: 11644473600 seconds
	const fileTimeEpochDiff = 11644473600

	unixTime := (fileTime / 10000000) - fileTimeEpochDiff

	// Convert to readable format
	if unixTime > 0 {
		t := time.Unix(unixTime, 0)
		return t.UTC().Format("2006-01-02 15:04:05 UTC") + fmt.Sprintf(" (%s)", fileTimeStr)
	}

	return fileTimeStr
}

func (l *LibraryEnumerateDomain) enumerateDomainTrusts(conn *ldap.Conn, baseDN string, maxResults *int) (*[]*domainfern.DomainTrust, []string) {
	var errors []string
	var trusts []*domainfern.DomainTrust
	sizeLimit := 0
	if maxResults != nil {
		sizeLimit = *maxResults
	}

	// Search for domain trust objects
	searchRequest := ldap.NewSearchRequest(
		fmt.Sprintf("CN=System,%s", baseDN),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, sizeLimit, 0, false,
		"(objectClass=trustedDomain)",
		[]string{"name", "trustDirection", "trustType", "trustAttributes", "flatName"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		errors = append(errors, fmt.Sprintf("LDAP search for domain trusts failed: %v", err))
		return nil, errors
	}

	for _, entry := range sr.Entries {
		trust := &domainfern.DomainTrust{}

		// Extract trust information
		if name := entry.GetAttributeValue("name"); name != "" {
			trust.TargetDomain = name
		}
		if flatName := entry.GetAttributeValue("flatName"); flatName != "" {
			trust.SourceDomain = flatName
		}
		if trustDirection := entry.GetAttributeValue("trustDirection"); trustDirection != "" {
			trust.TrustDirection = trustDirection
		}
		if trustType := entry.GetAttributeValue("trustType"); trustType != "" {
			trust.TrustType = trustType
		}
		if trustAttributes := entry.GetAttributeValue("trustAttributes"); trustAttributes != "" {
			trust.TrustAttributes = &trustAttributes
		}

		trusts = append(trusts, trust)
	}

	return &trusts, errors
}

// extractDomainFromBaseDN extracts the domain name from a baseDN
func (l *LibraryEnumerateDomain) extractDomainFromBaseDN(baseDN string) string {
	// Convert DC=corp,DC=auric-dynamics,DC=com to CORP.AURIC-DYNAMICS.COM
	parts := strings.Split(baseDN, ",")
	var domainParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			dcValue := strings.TrimPrefix(strings.ToUpper(part), "DC=")
			domainParts = append(domainParts, dcValue)
		}
	}
	return strings.Join(domainParts, ".")
}

// extractDomainSID extracts the domain SID from a full SID
func (l *LibraryEnumerateDomain) extractDomainSID(conn *ldap.Conn, baseDN string) string {
	// Search for the domain object to get the domain SID
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil || len(sr.Entries) == 0 {
		return ""
	}

	if sidBytes := sr.Entries[0].GetRawAttributeValue("objectSid"); len(sidBytes) > 0 {
		return l.convertSIDToString(string(sidBytes))
	}
	return ""
}
