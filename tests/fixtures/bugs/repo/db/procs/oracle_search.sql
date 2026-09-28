BEGIN
  v_sql := 'SELECT * FROM emp WHERE ename = ''' || p_name || '''';
  OPEN c FOR 'SELECT * FROM emp WHERE ename = :1' USING p_name;
END;
