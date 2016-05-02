USE [Auth]
GO
/****** Object:  UserDefinedTableType [dbo].[SecurityIdList]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE TYPE [dbo].[SecurityIdList] AS TABLE(
	[SecurityId] [uniqueidentifier] NOT NULL,
	PRIMARY KEY CLUSTERED 
(
	[SecurityId] ASC
)WITH (IGNORE_DUP_KEY = OFF)
)
GO
/****** Object:  UserDefinedFunction [dbo].[fnCheckAuthorization]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[fnCheckAuthorization] (
	@ResourceId UNIQUEIDENTIFIER
	,@SecurityIdList dbo.SecurityIdList READONLY
	,@PermissionId INT
	)
RETURNS BIT
AS
BEGIN
	DECLARE @IsOwner BIT = 0
	DECLARE @DenyCount INT = 0;
	DECLARE @AllowCount INT = 0;
	DECLARE @ExpandedSecurityIdList dbo.SecurityIdList;

	INSERT INTO @ExpandedSecurityIdList
	SELECT [SecurityId]
	FROM @SecurityIdLIST
	
	UNION
	
	SELECT [SecurityId]
	FROM dbo.[Role]
	WHERE NAME = 'Anonymous';

	--Owner->Deny->Allow->Nothing
	IF EXISTS (SELECT TOP 1 1 FROM dbo.GetResourceOwner(@ResourceId) o INNER JOIN @ExpandedSecurityIdList s ON o.[SecurityId] = s.[SecurityId])	
	BEGIN
		SELECT @IsOwner = 1
	END
	ELSE
	BEGIN
		SELECT @DenyCount = COUNT(*)
		FROM @ExpandedSecurityIdList AS [SecurityIds]
		INNER JOIN dbo.AccessPermissionJoin AS AP WITH (NOEXPAND) ON [SecurityIds].[SecurityId] = AP.[SecurityId]
			AND AP.ResourceId = @ResourceId
			AND AP.PermissionId = @PermissionId
			AND [Deny] = 1;

		IF @DenyCount = 0
		BEGIN
			SELECT @AllowCount = COUNT(*)
			FROM @ExpandedSecurityIdList AS [SecurityIds]
			INNER JOIN dbo.AccessPermissionJoin AS AP WITH (NOEXPAND) ON [SecurityIds].[SecurityId] = AP.[SecurityId]
				AND AP.ResourceId = @ResourceId
				AND AP.PermissionId = @PermissionId
				AND [Deny] = 0;
		END;
	END;

	--RETURN VALUE IS A BIT FIELD
	--None = 0x0, 
	--Access = 0x1
	DECLARE @RetVal INT = 0;

	IF @IsOwner = 1 OR (@DenyCount = 0 AND @AllowCount > 0)
	BEGIN
		SET @RetVal = 1;
	END;

	RETURN @RetVal;
END;

GO
/****** Object:  Table [dbo].[AccessControlList]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AccessControlList](
	[AccessControlListId] [bigint] IDENTITY(1,1) NOT NULL,
	[ResourceId] [uniqueidentifier] NOT NULL,
	[SecurityId] [uniqueidentifier] NOT NULL,
	[IsOwner] [bit] NOT NULL CONSTRAINT [DF_AccessControlList_IsOwner]  DEFAULT ((0)),
 CONSTRAINT [PK_AccessControlList] PRIMARY KEY CLUSTERED 
(
	[AccessControlListId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[AccessPermission]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AccessPermission](
	[AccessControlListId] [bigint] NOT NULL,
	[PermissionId] [int] NOT NULL,
	[Deny] [bit] NOT NULL CONSTRAINT [DF_AccessPermission_Deny]  DEFAULT ((0)),
 CONSTRAINT [PK_AccessPermission] PRIMARY KEY CLUSTERED 
(
	[AccessControlListId] ASC,
	[PermissionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Permission]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Permission](
	[PermissionId] [int] NOT NULL,
	[Name] [varchar](50) NOT NULL,
 CONSTRAINT [PK_Permission] PRIMARY KEY CLUSTERED 
(
	[PermissionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[Resource]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Resource](
	[ResourceId] [uniqueidentifier] NOT NULL CONSTRAINT [DF_Resource_ResourceId]  DEFAULT (newid()),
	[Name] [varchar](50) NOT NULL,
	[Description] [varchar](150) NULL,
	[IsActive] [bit] NOT NULL CONSTRAINT [DF_Resource_IsActive]  DEFAULT ((1)),
	[Created] [datetime] NOT NULL CONSTRAINT [DF_Resource_Created]  DEFAULT (getdate()),
 CONSTRAINT [PK_Resource] PRIMARY KEY CLUSTERED 
(
	[ResourceId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[ResourcePermission]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ResourcePermission](
	[ResourcePermissionId] [bigint] IDENTITY(1,1) NOT NULL,
	[ResourceId] [uniqueidentifier] NOT NULL,
	[PermissionId] [int] NOT NULL,
	[Deny] [bit] NOT NULL CONSTRAINT [DF_ResourcePermission_Deny]  DEFAULT ((0)),
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_ResourcePermission] PRIMARY KEY CLUSTERED 
(
	[ResourceId] ASC,
	[PermissionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Role]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Role](
	[RoleId] [bigint] IDENTITY(1,1) NOT NULL,
	[SecurityId] [uniqueidentifier] NOT NULL,
	[Name] [varchar](50) NOT NULL,
	[Description] [varchar](150) NULL,
	[IsActive] [bit] NOT NULL CONSTRAINT [DF_Role_IsActive]  DEFAULT ((1)),
	[UpdatedBy] [bigint] NOT NULL,
 CONSTRAINT [PK_Role] PRIMARY KEY CLUSTERED 
(
	[RoleId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[User]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[User](
	[UserId] [bigint] IDENTITY(1,1) NOT NULL,
	[SecurityId] [uniqueidentifier] NOT NULL,
	[Username] [varchar](50) NOT NULL,
 CONSTRAINT [PK_User] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[UserRole]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UserRole](
	[UserId] [bigint] NOT NULL,
	[RoleId] [bigint] NOT NULL,
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_UserRole] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  View [dbo].[AccessPermissionJoin]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[AccessPermissionJoin]	
WITH SCHEMABINDING
AS
     SELECT A.AccessControlListId,
            A.[ResourceId],
            A.[SecurityId],
            AP.PermissionId,
            AP.[Deny],
            P.Name
     FROM [dbo].AccessControlList A
          INNER JOIN [dbo].AccessPermission AP ON A.AccessControlListId = AP.AccessControlListId
          INNER JOIN [dbo].Permission P ON AP.PermissionId = P.PermissionId;


GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [PK_AccessPermissionJoin]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE UNIQUE CLUSTERED INDEX [PK_AccessPermissionJoin] ON [dbo].[AccessPermissionJoin]
(
	[AccessControlListId] ASC,
	[PermissionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  View [dbo].[AccessPermissionAllowDenyJoin]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[AccessPermissionAllowDenyJoin]	  
WITH SCHEMABINDING
AS SELECT A.[ResourceId], A.[SecurityId] AS [AllowedSecurityId], A.PermissionId, D.[SecurityId] AS [DeniedSecurityId]
   FROM
   (
	   SELECT AP.ResourceId, AP.SecurityId, AP.PermissionId
	   FROM dbo.AccessPermissionJoin AS AP WITH (NOEXPAND)
	   WHERE AP.[Deny] = 0
   ) AS A
   LEFT OUTER JOIN
   (
	   SELECT AP.[ResourceId], AP.[SecurityId], AP.PermissionId
	   FROM [dbo].AccessPermissionJoin AS AP WITH (NOEXPAND)
	   WHERE AP.[Deny] = 1
   ) AS D
   ON A.[ResourceId] = D.[ResourceId] AND 
	  A.PermissionId = D.PermissionId;


GO
/****** Object:  UserDefinedFunction [dbo].[GetResourceAccess]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[GetResourceAccess] (
	@SIDs dbo.SecurityIdList READONLY
	,@PermissionId INT
	)
RETURNS TABLE
AS
RETURN (
	   SELECT ResourceId
	   FROM dbo.AccessPermissionAllowDenyJoin AS AP
		   INNER JOIN @SIDs AS A ON AP.AllowedSecurityId = A.SecurityId
		   LEFT OUTER JOIN @SIDs AS D ON AP.DeniedSecurityId = D.SecurityId
	   WHERE AP.PermissionId = @PermissionId
		    AND D.SecurityId IS NULL
	   GROUP BY ResourceId
	   );

GO
/****** Object:  View [dbo].[UserRoleSecurityId]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[UserRoleSecurityId] 
WITH SCHEMABINDING
AS
     SELECT U.SecurityId AS UserSecurityId,
            R.SecurityId AS RoleSecurityId,
            U.UserId
     FROM dbo.[User] U
          INNER JOIN dbo.UserRole UR ON U.UserId = UR.UserId
          INNER JOIN dbo.[Role] R ON UR.RoleId = R.RoleId;



GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [IX_UserRoleSecurityId]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE UNIQUE CLUSTERED INDEX [IX_UserRoleSecurityId] ON [dbo].[UserRoleSecurityId]
(
	[UserId] ASC,
	[UserSecurityId] ASC,
	[RoleSecurityId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  UserDefinedFunction [dbo].[GetUserSecurityIdRelatedSecurityIds]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[GetUserSecurityIdRelatedSecurityIds]
(@userSecurityId UNIQUEIDENTIFIER
)
RETURNS TABLE
AS
     RETURN
(
    -- User
    SELECT @userSecurityId AS SecurityId,
           'User' AS SecurityIdType
    UNION ALL
    -- Users's Roles
    SELECT RoleSecurityId,
           'User Role'
    FROM [dbo].UserRoleSecurityId
    WHERE UserSecurityId = @userSecurityId
);

GO
/****** Object:  View [dbo].[ResourceOwnerRole]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[ResourceOwnerRole]
WITH SCHEMABINDING
AS
SELECT
	ACL.ResourceId,
	R.RoleId,
	R.SecurityId,
	R.Name
FROM
	dbo.AccessControlList ACL
	INNER JOIN dbo.[Role] R ON ACL.SecurityId = R.SecurityId
WHERE
	ACL.IsOwner = 1


GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [PK_ResourceOwnerRole]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE UNIQUE CLUSTERED INDEX [PK_ResourceOwnerRole] ON [dbo].[ResourceOwnerRole]
(
	[ResourceId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  View [dbo].[ResourceOwnerUser]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



CREATE VIEW [dbo].[ResourceOwnerUser] 
WITH SCHEMABINDING
 
AS
SELECT
	ACL.ResourceId,
	U.UserID,
	U.SecurityId,
	U.Username
FROM
	dbo.AccessControlList ACL
	INNER JOIN dbo.[User] U ON ACL.SecurityId = U.SecurityId
WHERE
	ACL.IsOwner = 1



GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [PK_ResourceOwnerUser]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE UNIQUE CLUSTERED INDEX [PK_ResourceOwnerUser] ON [dbo].[ResourceOwnerUser]
(
	[ResourceId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  UserDefinedFunction [dbo].[GetResourceOwner]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[GetResourceOwner] 
(	
	@ResourceId UNIQUEIDENTIFIER
)
RETURNS TABLE 
AS
RETURN 
(
	SELECT
		'U' AS [Type],
		UserId AS [Id],
		SecurityId AS [SecurityId],
		Username AS [Name]
	FROM	dbo.ResourceOwnerUser WITH (NOEXPAND) WHERE ResourceId = @ResourceId
	UNION ALL
	SELECT
		'R',
		RoleId,
		SecurityId,
		Name
	FROM dbo.ResourceOwnerRole WITH (NOEXPAND) WHERE ResourceId = @ResourceId
)

GO
/****** Object:  View [dbo].[ResourceAccess]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[ResourceAccess]
AS
     SELECT B.SecurityId,
            B.ResourceId,
            A.Name AS ResourceName,
            B.AccessControlListId,
            C.PermissionId,
            D.Name AS PermissionName,
            C.[Deny]
     FROM dbo.[Resource] AS A
          INNER JOIN [dbo].AccessControlList AS B ON(A.ResourceId = B.ResourceId)
          INNER JOIN [dbo].AccessPermission AS C ON B.AccessControlListId = C.AccessControlListId
          INNER JOIN [dbo].Permission AS D ON C.PermissionId = D.PermissionId;

GO
/****** Object:  Index [IX_AccessControlList]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE UNIQUE NONCLUSTERED INDEX [IX_AccessControlList] ON [dbo].[AccessControlList]
(
	[ResourceId] ASC,
	[SecurityId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, IGNORE_DUP_KEY = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  Index [IX_ResourcePermission]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE NONCLUSTERED INDEX [IX_ResourcePermission] ON [dbo].[ResourcePermission]
(
	[ResourcePermissionId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [IX_AccessPermission_ResourceIdDeny]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE NONCLUSTERED INDEX [IX_AccessPermission_ResourceIdDeny] ON [dbo].[AccessPermissionJoin]
(
	[ResourceId] ASC,
	[Deny] ASC
)
INCLUDE ( 	[Name],
	[PermissionId],
	[SecurityId]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [IX_AccessPermissionJoin_PermissionResourceId]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE NONCLUSTERED INDEX [IX_AccessPermissionJoin_PermissionResourceId] ON [dbo].[AccessPermissionJoin]
(
	[PermissionId] ASC,
	[ResourceId] ASC
)
INCLUDE ( 	[SecurityId]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
SET ARITHABORT ON
SET CONCAT_NULL_YIELDS_NULL ON
SET QUOTED_IDENTIFIER ON
SET ANSI_NULLS ON
SET ANSI_PADDING ON
SET ANSI_WARNINGS ON
SET NUMERIC_ROUNDABORT OFF

GO
/****** Object:  Index [IX_AccessPermissionJoin_SecurityIdPermission]    Script Date: 4/29/2016 6:22:52 PM ******/
CREATE NONCLUSTERED INDEX [IX_AccessPermissionJoin_SecurityIdPermission] ON [dbo].[AccessPermissionJoin]
(
	[Deny] ASC,
	[SecurityId] ASC,
	[PermissionId] ASC
)
INCLUDE ( 	[ResourceId]) WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [dbo].[AccessPermission]  WITH CHECK ADD  CONSTRAINT [FK_AccessPermission_AccessControlList] FOREIGN KEY([AccessControlListId])
REFERENCES [dbo].[AccessControlList] ([AccessControlListId])
GO
ALTER TABLE [dbo].[AccessPermission] CHECK CONSTRAINT [FK_AccessPermission_AccessControlList]
GO
ALTER TABLE [dbo].[AccessPermission]  WITH CHECK ADD  CONSTRAINT [FK_AccessPermission_Permission] FOREIGN KEY([PermissionId])
REFERENCES [dbo].[Permission] ([PermissionId])
GO
ALTER TABLE [dbo].[AccessPermission] CHECK CONSTRAINT [FK_AccessPermission_Permission]
GO
ALTER TABLE [dbo].[ResourcePermission]  WITH CHECK ADD  CONSTRAINT [FK_ResourcePermission_Permission] FOREIGN KEY([PermissionId])
REFERENCES [dbo].[Permission] ([PermissionId])
GO
ALTER TABLE [dbo].[ResourcePermission] CHECK CONSTRAINT [FK_ResourcePermission_Permission]
GO
ALTER TABLE [dbo].[ResourcePermission]  WITH CHECK ADD  CONSTRAINT [FK_ResourcePermission_Resource] FOREIGN KEY([ResourceId])
REFERENCES [dbo].[Resource] ([ResourceId])
GO
ALTER TABLE [dbo].[ResourcePermission] CHECK CONSTRAINT [FK_ResourcePermission_Resource]
GO
ALTER TABLE [dbo].[Role]  WITH CHECK ADD  CONSTRAINT [FK_Role_User] FOREIGN KEY([UpdatedBy])
REFERENCES [dbo].[User] ([UserId])
GO
ALTER TABLE [dbo].[Role] CHECK CONSTRAINT [FK_Role_User]
GO
ALTER TABLE [dbo].[UserRole]  WITH CHECK ADD  CONSTRAINT [FK_UserRole_Role] FOREIGN KEY([RoleId])
REFERENCES [dbo].[Role] ([RoleId])
GO
ALTER TABLE [dbo].[UserRole] CHECK CONSTRAINT [FK_UserRole_Role]
GO
ALTER TABLE [dbo].[UserRole]  WITH CHECK ADD  CONSTRAINT [FK_UserRole_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([UserId])
GO
ALTER TABLE [dbo].[UserRole] CHECK CONSTRAINT [FK_UserRole_User]
GO
/****** Object:  StoredProcedure [dbo].[AddUserToRoleByName]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[AddUserToRoleByName]
(
	@Username varchar(50),
	@Rolename varchar(50)
)	
AS
	DECLARE @UserId int;
	DECLARE @RoleId int;

	SELECT @UserId = UserId FROM dbo.[User] WHERE Username = @Username;
	SELECT @RoleId = RoleId FROM dbo.[Role] WHERE Name = @Rolename;

	IF NOT EXISTS(SELECT 1 FROM dbo.[UserRole] WHERE UserId = @UserId AND RoleID = @RoleId)
	BEGIN
		INSERT dbo.[UserRole] (UserID, RoleID) VALUES (@UserID, @RoleID);
	END


GO
/****** Object:  StoredProcedure [dbo].[CheckAuthorization]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[CheckAuthorization] (
	@ResourceId UNIQUEIDENTIFIER
	,@SecurityIdList dbo.SecurityIdList READONLY
	,@PermissionId INT
	)
AS
BEGIN
	DECLARE @IsOwner BIT = 0
	DECLARE @DenyCount INT = 0;
	DECLARE @AllowCount INT = 0;
	DECLARE @ExpandedSecurityIdList dbo.SecurityIdList;

	INSERT INTO @ExpandedSecurityIdList
	SELECT [SecurityId]
	FROM @SecurityIdLIST
	
	UNION
	
	SELECT [SecurityId]
	FROM dbo.[Role]
	WHERE NAME = 'Anonymous';

	--Owner->Deny->Allow->Nothing
	IF EXISTS (SELECT TOP 1 1 FROM dbo.GetResourceOwner(@ResourceId) o INNER JOIN @ExpandedSecurityIdList s ON o.[SecurityId] = s.[SecurityId])	
	BEGIN
		SELECT @IsOwner = 1
	END
	ELSE
	BEGIN
		SELECT @DenyCount = COUNT(*)
		FROM @ExpandedSecurityIdList AS [SecurityIds]
		INNER JOIN dbo.AccessPermissionJoin AS AP WITH (NOEXPAND) ON [SecurityIds].[SecurityId] = AP.[SecurityId]
			AND AP.ResourceId = @ResourceId
			AND AP.PermissionId = @PermissionId
			AND [Deny] = 1;

		IF @DenyCount = 0
		BEGIN
			SELECT @AllowCount = COUNT(*)
			FROM @ExpandedSecurityIdList AS [SecurityIds]
			INNER JOIN dbo.AccessPermissionJoin AS AP WITH (NOEXPAND) ON [SecurityIds].[SecurityId] = AP.[SecurityId]
				AND AP.ResourceId = @ResourceId
				AND AP.PermissionId = @PermissionId
				AND [Deny] = 0;
		END;
	END;

	--RETURN VALUE IS A BIT FIELD
	--None = 0x0, 
	--Access = 0x1
	DECLARE @RetVal INT = 0;

	IF @IsOwner = 1 OR (@DenyCount = 0 AND @AllowCount > 0)
	BEGIN
		SET @RetVal = 1;
	END;

	SELECT @RetVal;
END;

GO
/****** Object:  StoredProcedure [dbo].[ListSecurityRolesByUserName]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[ListSecurityRolesByUserName](@UserName VARCHAR(50))
AS
     SELECT R.RoleID,
            R.SecurityId,
            R.Name
     FROM dbo.[Role] R
          INNER JOIN dbo.[UserRole] UR ON R.RoleId = UR.RoleId
          INNER JOIN dbo.[User] U ON UR.UserId = U.UserId
     WHERE U.Username = @UserName;

GO
/****** Object:  StoredProcedure [dbo].[RoleExists]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[RoleExists]
(
	@RoleName varchar(50)
)
AS
	SELECT CAST(1 as bit) FROM dbo.[Role] WHERE Name = @RoleName


GO
/****** Object:  StoredProcedure [dbo].[spGetUserPermissions]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[spGetUserPermissions] (@userID INT)
AS
BEGIN
	WITH AllSecurityId
	AS (
		SELECT [User].[SecurityId]
		FROM dbo.[User]
		WHERE [User].UserID = @userID
		
		UNION
		
		SELECT [Role].[SecurityId]
		FROM dbo.[UserRole]
		INNER JOIN dbo.[Role] ON UserRole.RoleID = [Role].RoleID
		WHERE UserRole.UserID = @userID
		)
		,AllRResourceId
	AS (
		SELECT r.Name
			,ap.PermissionId
			,ap.[Deny]
			,acl.IsOwner
		FROM AllSecurityId asi	 
		INNER JOIN dbo.AccessControlList acl ON asi.SecurityId = acl.SecurityId
		INNER JOIN dbo.AccessPermission ap ON acl.AccessControlListId  = ap.AccessControlListId
		INNER JOIN dbo.[Resource] r ON acl.ResourceId = r.ResourceId
		)
	SELECT DISTINCT NAME AS ResourceName
		,PermissionId AS Permission
	FROM AllRResourceId
	WHERE [Deny] = 0;
END;

GO
/****** Object:  StoredProcedure [dbo].[spGrantPermission]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
/***************************************************************************************************
*
* Created By: Arunkumar K
* Created Date: 04/27/2016
* Notes/Description: This will grant permission to the specified resource
*
* Example Usage: EXEC Config.spGrantPermission '<RID GUID>', '<SID GUID>', -3
*
* Updated By:
* Updated Date:
* Notes: <Repeat this section for every update>
* 
***************************************************************************************************/
CREATE PROCEDURE [dbo].[spGrantPermission]
	@resourceId UNIQUEIDENTIFIER,
	@securityId UNIQUEIDENTIFIER,
	@permissionId INT,
	@isOwner BIT = 0
AS

SET NOCOUNT ON

BEGIN TRANSACTION 

BEGIN TRY

	DECLARE			
		@rowsAffected INT = 2,
		@SIDList dbo.SecurityIdList

    INSERT INTO @SIDList VALUES (@securityId)

	-- Check to see if the user already has the permission before trying to add it again
	IF Config.fnCheckAuthorization(@resourceId, @SIDList, @permissionId) = 0
	BEGIN
		INSERT INTO dbo.AccessControlList (ResourceId, SecurityId, IsOwner) VALUES (@resourceId, @securityId, @isOwner)
		SET @rowsAffected = @@ROWCOUNT
		INSERT INTO dbo.AccessPermission (AccessControlListId, PermissionId, [Deny]) VALUES (SCOPE_IDENTITY(), @permissionId, 0)
		SET @rowsAffected = @rowsAffected + @@ROWCOUNT
	END

	-- Check for logical business errors here
	IF @rowsAffected <> 2
		RAISERROR (50017, 11, 1, 'Config.spGrantPermission')
END TRY

BEGIN CATCH
	-- Error handling here
	DECLARE @errNumber int, @errSeverity int, @errState int, @errProcedure varchar(500), @errLine int, @errMmessage varchar(500)
	SELECT @errNumber = ERROR_NUMBER(), @errSeverity = ERROR_SEVERITY(), @errState = ERROR_STATE(), @errProcedure = ERROR_PROCEDURE(), @errLine = ERROR_LINE(), @errMmessage = ERROR_MESSAGE()

	IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION 
	THROW
END CATCH

IF @@TRANCOUNT > 0 COMMIT TRANSACTION 

GO
/****** Object:  StoredProcedure [dbo].[spRevokePermission]    Script Date: 4/29/2016 6:22:52 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
/***************************************************************************************************
*
* Created By: Arunkumar K
* Created Date: 04/27/2016
* Notes/Description: This will revoke the permission for a resource (ResourceId) from the user or group
* represented by the specified securityId
*
* Example Usage: EXEC [dbo].[spRevokePermission] '<resourceId GUId>', '<securityId GUId>', -3
* 
* Updated By:
* Updated Date:
* Notes: <Repeat this section for every update>
* 
***************************************************************************************************/
CREATE PROCEDURE [dbo].[spRevokePermission]
	@resourceId UNIQUEIdENTIFIER,
	@securityId UNIQUEIdENTIFIER,
	@permissionId INT
AS

SET NOCOUNT ON

BEGIN TRANSACTION 

BEGIN TRY

	DECLARE	
		@rowsAffected INT = 2,
		@accessControlListId INT,
		@securityIdList dbo.SecurityIdList

    INSERT INTO @securityIdList VALUES (@securityId)

	-- Check to see if the user already has the permission before trying to revoke it
	IF Config.fnCheckAuthorization(@resourceId, @securityIdList, @permissionId) = 1
	BEGIN
		SET @AccessControlListId = (SELECT A.AccessControlListId FROM dbo.AccessControlList A INNER JOIN dbo.AccessPermission B ON B.AccessControlListId = A.AccessControlListId WHERE A.ResourceId = @resourceId AND A.SecurityId = @securityId AND B.PermissionId = @permissionId)

		DELETE dbo.AccessPermission WHERE AccessControlListId = @accessControlListId AND PermissionId = @permissionId
		SET @rowsAffected = @@ROWCOUNT
		DELETE dbo.AccessControlList WHERE AccessControlListId = @accessControlListId
		SET @rowsAffected = @rowsAffected + @@ROWCOUNT
	END

	-- Check for logical business errors here
	IF @rowsAffected <> 2
		RAISERROR (50017, 11, 1, 'Config.spRevokePermission')
END TRY

BEGIN CATCH
	-- Error handling here
	DECLARE @errNumber int, @errSeverity int, @errState int, @errProcedure varchar(500), @errLine int, @errMmessage varchar(500)
	SELECT @errNumber = ERROR_NUMBER(), @errSeverity = ERROR_SEVERITY(), @errState = ERROR_STATE(), @errProcedure = ERROR_PROCEDURE(), @errLine = ERROR_LINE(), @errMmessage = ERROR_MESSAGE()

	IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION 

	THROW
END CATCH

IF @@TRANCOUNT > 0 COMMIT TRANSACTION 


GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Either User.SecurityId or Role.SecurityId.' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'AccessControlList', @level2type=N'COLUMN',@level2name=N'SecurityId'
GO


INSERT INTO [dbo].[Permission] ([PermissionId], [Name]) VALUES (-4, 'Delete')
INSERT INTO [dbo].[Permission] ([PermissionId], [Name]) VALUES (-3, 'Update')
INSERT INTO [dbo].[Permission] ([PermissionId], [Name]) VALUES (-2, 'Read')
INSERT INTO [dbo].[Permission] ([PermissionId], [Name]) VALUES (-1, 'Create')