import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from sklearn.linear_model import LinearRegression
from models import Attendance, User

class AttendanceAnalytics:
    def __init__(self):
        self.attendance_threshold = 75  

    def get_student_attendance_data(self, student_id, days=30):
        
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        attendance_records = Attendance.query.filter(
            Attendance.student_id == student_id,
            Attendance.date >= start_date,
            Attendance.date <= end_date
        ).all()

        return attendance_records

    def calculate_attendance_percentage(self, student_id, days=30):
        
        records = self.get_student_attendance_data(student_id, days)
        if not records:
            return 0

        present_count = len([r for r in records if r.status == 'Present'])
        total_count = len(records)

        return (present_count / total_count) * 100 if total_count > 0 else 0

    def predict_attendance_trend(self, student_id, days=30):
        
        records = self.get_student_attendance_data(student_id, days)
        if len(records) < 5:  
            return None

        
        dates = [(r.date - records[0].date).days for r in records]
        attendance_values = [1 if r.status == 'Present' else 0 for r in records]

        
        rolling_avg = []
        window = 7
        for i in range(len(attendance_values)):
            start_idx = max(0, i - window + 1)
            avg = sum(attendance_values[start_idx:i+1]) / (i - start_idx + 1)
            rolling_avg.append(avg * 100)

        if len(rolling_avg) < 3:
            return None

        
        X = np.array(dates[-len(rolling_avg):]).reshape(-1, 1)
        y = np.array(rolling_avg)

        model = LinearRegression()
        model.fit(X, y)

        
        future_dates = [dates[-1] + i for i in range(1, 8)]
        future_X = np.array(future_dates).reshape(-1, 1)
        predictions = model.predict(future_X)

        return {
            'current_trend': rolling_avg[-1],
            'predicted_avg': np.mean(predictions),
            'trend_slope': model.coef_[0],
            'is_declining': model.coef_[0] < -0.5
        }

    def get_at_risk_students(self, limit=5):
        
        students = User.query.filter_by(role='student', status='active').all()
        at_risk = []

        for student in students:
            current_percentage = self.calculate_attendance_percentage(student.id)
            trend = self.predict_attendance_trend(student.id)

            risk_score = 0
            if current_percentage < self.attendance_threshold:
                risk_score += 3
            elif current_percentage < self.attendance_threshold + 10:
                risk_score += 2

            if trend and trend['is_declining']:
                risk_score += 2

            if trend and trend['predicted_avg'] < self.attendance_threshold:
                risk_score += 1

            if risk_score > 0:
                at_risk.append({
                    'student': student,
                    'current_percentage': round(current_percentage, 1),
                    'risk_score': risk_score,
                    'trend': trend
                })

        
        at_risk.sort(key=lambda x: x['risk_score'], reverse=True)
        return at_risk[:limit]

    def get_class_attendance_summary(self, class_name):
        
        students = User.query.filter_by(role='student', class_name=class_name, status='active').all()
        class_data = []

        for student in students:
            percentage = self.calculate_attendance_percentage(student.id)
            class_data.append({
                'student_name': student.username,
                'attendance_percentage': round(percentage, 1)
            })

        return class_data

    def get_attendance_patterns(self):
        
        attendance_records = Attendance.query.all()

        day_patterns = defaultdict(lambda: {'present': 0, 'absent': 0})

        for record in attendance_records:
            day_name = record.date.strftime('%A')
            if record.status == 'Present':
                day_patterns[day_name]['present'] += 1
            else:
                day_patterns[day_name]['absent'] += 1

        patterns = {}
        for day, data in day_patterns.items():
            total = data['present'] + data['absent']
            patterns[day] = {
                'attendance_rate': (data['present'] / total * 100) if total > 0 else 0,
                'total_classes': total
            }

        return patterns

    def get_subject_wise_attendance(self):
        
        attendance_records = Attendance.query.all()

        subject_data = defaultdict(lambda: {'present': 0, 'absent': 0})

        for record in attendance_records:
            if record.status == 'Present':
                subject_data[record.subject]['present'] += 1
            else:
                subject_data[record.subject]['absent'] += 1

        subjects = {}
        for subject, data in subject_data.items():
            total = data['present'] + data['absent']
            subjects[subject] = {
                'attendance_rate': (data['present'] / total * 100) if total > 0 else 0,
                'total_classes': total,
                'present_count': data['present'],
                'absent_count': data['absent']
            }

        return subjects

    def generate_attendance_chart_data(self, student_id, days=30):
        
        records = self.get_student_attendance_data(student_id, days)

        
        daily_data = defaultdict(int)
        for record in records:
            date_str = record.date.strftime('%Y-%m-%d')
            daily_data[date_str] += 1 if record.status == 'Present' else 0

        
        dates = sorted(daily_data.keys())
        attendance_values = [daily_data[date] for date in dates]

        return {
            'dates': dates,
            'attendance': attendance_values
        }

    def get_admin_insights(self):
        
        at_risk_students = self.get_at_risk_students()
        attendance_patterns = self.get_attendance_patterns()
        subject_stats = self.get_subject_wise_attendance()

        
        total_students = User.query.filter_by(role='student', status='active').count()
        total_records = Attendance.query.count()
        present_records = Attendance.query.filter_by(status='Present').count()
        overall_percentage = (present_records / total_records * 100) if total_records > 0 else 0

        return {
            'at_risk_students': at_risk_students,
            'attendance_patterns': attendance_patterns,
            'subject_stats': subject_stats,
            'overall_stats': {
                'total_students': total_students,
                'total_records': total_records,
                'overall_percentage': round(overall_percentage, 1)
            }
        }

    def get_teacher_insights(self, teacher_id):
        
        from models import TeacherClassAssignment

        assignments = TeacherClassAssignment.query.filter_by(teacher_id=teacher_id).all()
        teacher_insights = {
            'classes_taught': len(assignments),
            'subject_performance': {},
            'at_risk_in_classes': []
        }

        for assignment in assignments:
            
            students = User.query.filter_by(
                role='student',
                class_name=assignment.class_name,
                status='active'
            ).all()

            class_performance = []
            for student in students:
                percentage = self.calculate_attendance_percentage(student.id)
                class_performance.append(percentage)

                if percentage < self.attendance_threshold:
                    teacher_insights['at_risk_in_classes'].append({
                        'student': student,
                        'class': assignment.class_name,
                        'subject': assignment.subject,
                        'percentage': round(percentage, 1)
                    })

            if class_performance:
                avg_performance = sum(class_performance) / len(class_performance)
                teacher_insights['subject_performance'][assignment.subject] = {
                    'average_attendance': round(avg_performance, 1),
                    'student_count': len(students)
                }

        return teacher_insights
