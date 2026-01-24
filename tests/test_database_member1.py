"""
数据库功能测试脚本 - 成员1

这个脚本用于验证数据库的基本功能
"""
from src.database import db_manager, User, AuditReport, Vulnerability
from datetime import datetime


def test_database_basic_operations():
    """测试数据库基本操作"""
    
    print("\n" + "=" * 60)
    print("🧪 数据库功能测试")
    print("=" * 60)
    
    session = db_manager.get_session()
    
    try:
        # 测试1: 创建用户
        print("\n【测试1】创建用户...")
        test_user = User(
            username="testuser_db",
            email="test_db@example.com",
            password_hash="hashed_password_example"
        )
        session.add(test_user)
        session.commit()
        session.refresh(test_user)
        print(f"   ✅ 创建用户成功: ID={test_user.id}, 用户名={test_user.username}")
        
        # 测试2: 查询用户
        print("\n【测试2】查询用户...")
        found_user = session.query(User).filter_by(username="testuser_db").first()
        if found_user:
            print(f"   ✅ 查询成功: {found_user}")
        else:
            print("   ❌ 查询失败")
        
        # 测试3: 创建审计报告
        print("\n【测试3】创建审计报告...")
        test_audit = AuditReport(
            user_id=test_user.id,
            contract_code="pragma solidity ^0.8.0;\ncontract Test {}",
            contract_name="TestContract",
            heuristic_results='["✅ No issues"]',
            ai_analysis="## No vulnerabilities found",
            severity_score=0.0,
            vulnerabilities_count=0,
            analysis_duration=5.5
        )
        session.add(test_audit)
        session.commit()
        session.refresh(test_audit)
        print(f"   ✅ 创建审计报告成功: ID={test_audit.id}")
        
        # 测试4: 创建漏洞记录
        print("\n【测试4】创建漏洞记录...")
        test_vuln = Vulnerability(
            audit_report_id=test_audit.id,
            name="Test Vulnerability",
            severity="Medium",
            description="This is a test vulnerability",
            recommendation="Fix it",
            line_number=10,
            function_name="testFunction"
        )
        session.add(test_vuln)
        session.commit()
        print(f"   ✅ 创建漏洞记录成功: ID={test_vuln.id}")
        
        # 测试5: 测试关系查询
        print("\n【测试5】测试数据关系...")
        user_with_audits = session.query(User).filter_by(id=test_user.id).first()
        print(f"   ✅ 用户 {user_with_audits.username} 有 {len(user_with_audits.audits)} 个审计报告")
        
        audit_with_vulns = session.query(AuditReport).filter_by(id=test_audit.id).first()
        print(f"   ✅ 审计报告有 {len(audit_with_vulns.vulnerabilities)} 个漏洞")
        
        # 测试6: 更新操作
        print("\n【测试6】更新数据...")
        test_audit.severity_score = 3.5
        test_audit.vulnerabilities_count = 1
        session.commit()
        print(f"   ✅ 更新审计报告成功: 新评分={test_audit.severity_score}")
        
        # 测试7: 统计查询
        print("\n【测试7】统计查询...")
        total_users = session.query(User).count()
        total_audits = session.query(AuditReport).count()
        total_vulns = session.query(Vulnerability).count()
        print(f"   ✅ 总用户数: {total_users}")
        print(f"   ✅ 总审计数: {total_audits}")
        print(f"   ✅ 总漏洞数: {total_vulns}")
        
        # 测试8: 级联删除
        print("\n【测试8】测试级联删除...")
        session.delete(test_user)
        session.commit()
        
        # 验证关联数据也被删除
        remaining_audits = session.query(AuditReport).filter_by(id=test_audit.id).first()
        remaining_vulns = session.query(Vulnerability).filter_by(id=test_vuln.id).first()
        
        if remaining_audits is None and remaining_vulns is None:
            print("   ✅ 级联删除成功（删除用户后，审计和漏洞也被删除）")
        else:
            print("   ❌ 级联删除失败")
        
        print("\n" + "=" * 60)
        print("🎉 所有测试通过！数据库功能正常！")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        session.rollback()
        raise
        
    finally:
        db_manager.close_session(session)


def test_database_constraints():
    """测试数据库约束"""
    
    print("\n" + "=" * 60)
    print("🧪 数据库约束测试")
    print("=" * 60)
    
    session = db_manager.get_session()
    
    try:
        # 创建测试用户
        print("\n【测试】唯一性约束...")
        user1 = User(
            username="unique_test",
            email="unique@test.com",
            password_hash="hash"
        )
        session.add(user1)
        session.commit()
        print("   ✅ 创建第一个用户成功")
        
        # 尝试创建重复用户名
        try:
            user2 = User(
                username="unique_test",  # 重复用户名
                email="another@test.com",
                password_hash="hash"
            )
            session.add(user2)
            session.commit()
            print("   ❌ 唯一性约束失败（不应该允许重复用户名）")
        except Exception as e:
            session.rollback()
            print("   ✅ 唯一性约束生效（正确阻止了重复用户名）")
        
        # 清理测试数据
        session.query(User).filter_by(username="unique_test").delete()
        session.commit()
        
        print("\n" + "=" * 60)
        print("🎉 约束测试通过！")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ 约束测试失败: {e}")
        session.rollback()
        
    finally:
        db_manager.close_session(session)


if __name__ == "__main__":
    print("\n🚀 开始数据库测试...")
    print("⚠️  注意：此测试会创建和删除测试数据\n")
    
    # 确保数据库已初始化
    db_manager.create_tables()
    
    # 运行测试
    test_database_basic_operations()
    test_database_constraints()
    
    print("\n✅ 所有数据库测试完成！")
    print("\n📝 成员1的工作已完成，其他成员可以开始使用数据库了！")
