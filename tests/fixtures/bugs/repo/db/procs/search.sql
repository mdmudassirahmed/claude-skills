-- dynamic search: SET @sql = 'SELECT * FROM T WHERE Name = ''' + @Name + '''';
CREATE PROCEDURE SearchCustomers @Name NVARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    SET @sql = 'SELECT * FROM Customers WHERE Name = ''' + @Name + '''';
    EXEC(@sql);
    EXEC sp_executesql N'SELECT * FROM Customers WHERE Name = @n', N'@n NVARCHAR(100)', @n = @Name;
    SELECT * FROM Orders WHERE Id = 1;
END
